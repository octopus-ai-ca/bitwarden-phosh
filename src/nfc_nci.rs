//! Clés FIDO2 par la puce NFC intégrée d'un téléphone, via un démon qui relaie
//! les trames NCI brutes sur un socket Unix (voir `contrib/nci-bridge/`).
//!
//! C'est le repli lorsque le service PC/SC (`pcscd`) est absent : la puce NFC
//! des téléphones (p. ex. Samsung S3NRN81 du Galaxy A5 2017, pilote `sec-nfc`)
//! n'est pas exposée par PC/SC.
//!
//! Couches :
//! 1. [`Nci`] : protocole NCI (NFC Forum) — découverte en mode lecteur NFC-A,
//!    activation de l'interface ISO-DEP, échange de paquets de données avec
//!    fragmentation et contrôle de flux par crédits.
//! 2. [`NciToken`] : CTAP sur NFC (APDU ISO 7816-4) — sélection de l'applet
//!    FIDO, chaînage des commandes, `GET RESPONSE` et attente `9100`.
//!    Il implémente `Token` de `webauthn-authenticator-rs`, qui gère CTAP2.

use std::collections::VecDeque;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::{Instant, timeout};
use webauthn_authenticator_rs::{
    error::{CtapError, WebauthnCError},
    transport::Token,
    ui::UiCallback,
};
use webauthn_rs_proto::AuthenticatorTransport;

/// Socket par défaut du démon du Galaxy A5 2017 (`a5y17lte-nfcd`).
pub const DEFAULT_SOCKET: &str = "/run/a5y17lte-nfc/nci.sock";

/// Chemin du socket (`COFFRE_NCI_SOCKET` permet de le changer).
pub fn socket_path() -> PathBuf {
    std::env::var_os("COFFRE_NCI_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

// Types de message NCI (champ MT).
const MT_DATA: u8 = 0;
const MT_CMD: u8 = 1;
const MT_RSP: u8 = 2;
const MT_NTF: u8 = 3;

// Groupes et opcodes utilisés.
const GID_CORE: u8 = 0x0;
const GID_RF: u8 = 0x1;
const OID_CORE_CONN_CREDITS: u8 = 0x06;
const OID_CORE_GENERIC_ERROR: u8 = 0x07;
const OID_CORE_INTERFACE_ERROR: u8 = 0x08;
const OID_RF_DISCOVER_MAP: u8 = 0x00;
const OID_RF_DISCOVER: u8 = 0x03;
const OID_RF_DISCOVER_SELECT: u8 = 0x04;
const OID_RF_INTF_ACTIVATED: u8 = 0x05;
const OID_RF_DEACTIVATE: u8 = 0x06;

const STATUS_OK: u8 = 0x00;
const STATUS_SEMANTIC_ERROR: u8 = 0x06;

const PROTOCOL_ISO_DEP: u8 = 0x04;
const INTERFACE_ISO_DEP: u8 = 0x02;
const MODE_POLL: u8 = 0x01;
const TECH_NFC_A_PASSIVE_POLL: u8 = 0x00;

const DEACTIVATE_IDLE: u8 = 0x00;
const DEACTIVATE_DISCOVERY: u8 = 0x03;

/// Connexion RF statique, utilisée pour les données de l'interface activée.
const STATIC_RF_CONN: u8 = 0;
/// Crédits illimités (contrôle de flux désactivé par le contrôleur).
const CREDITS_UNLIMITED: u8 = 0xFF;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const DATA_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum NciError {
    #[error("E/S NCI : {0}")]
    Io(#[from] std::io::Error),
    #[error("délai NCI dépassé")]
    Timeout,
    #[error("commande NCI {gid:#x}/{oid:#x} refusée (statut {status:#04x})")]
    Status { gid: u8, oid: u8, status: u8 },
    #[error("réponse NCI mal formée")]
    Malformed,
    #[error("la clé a été retirée du lecteur")]
    TagLost,
    #[error("erreur RF (statut {0:#04x})")]
    Interface(u8),
    #[error("opération annulée")]
    Cancelled,
}

impl From<NciError> for WebauthnCError {
    fn from(e: NciError) -> Self {
        eprintln!("NCI : {e}");
        match e {
            NciError::Cancelled => WebauthnCError::Cancelled,
            NciError::Timeout => WebauthnCError::Ctap(CtapError::Ctap2ActionTimeout),
            _ => WebauthnCError::ApduTransmission,
        }
    }
}

/// Paquet NCI (en-tête de 3 octets + charge utile).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Packet {
    mt: u8,
    /// Indicateur de fragment : d'autres paquets suivent.
    pbf: bool,
    /// GID (contrôle) ou identifiant de connexion (données).
    gid: u8,
    /// OID (contrôle); 0 pour les données.
    oid: u8,
    payload: Vec<u8>,
}

impl Packet {
    fn control(mt: u8, gid: u8, oid: u8, payload: Vec<u8>) -> Self {
        Self {
            mt,
            pbf: false,
            gid,
            oid,
            payload,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.payload.len());
        out.push((self.mt << 5) | (u8::from(self.pbf) << 4) | (self.gid & 0x0F));
        out.push(if self.mt == MT_DATA {
            0
        } else {
            self.oid & 0x3F
        });
        out.push(self.payload.len() as u8);
        out.extend_from_slice(&self.payload);
        out
    }

    fn is(&self, mt: u8, gid: u8, oid: u8) -> bool {
        self.mt == mt && self.gid == gid && self.oid == oid
    }
}

/// Interface RF activée sur une carte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activation {
    pub discovery_id: u8,
    pub interface: u8,
    pub protocol: u8,
    pub max_payload: u8,
    pub credits: u8,
}

/// Dialogue NCI sur un flux d'octets (socket du démon, ou simulateur en test).
pub struct Nci<S> {
    io: S,
    /// Notifications et données reçues en attendant une réponse.
    pending: VecDeque<Packet>,
    max_payload: usize,
    credits: u8,
    active: bool,
}

impl<S> fmt::Debug for Nci<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nci")
            .field("max_payload", &self.max_payload)
            .field("credits", &self.credits)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Nci<S> {
    pub fn new(io: S) -> Self {
        Self {
            io,
            pending: VecDeque::new(),
            max_payload: 255,
            credits: CREDITS_UNLIMITED,
            active: false,
        }
    }

    async fn read_packet(&mut self) -> Result<Packet, NciError> {
        let mut header = [0u8; 3];
        self.io.read_exact(&mut header).await?;
        let mut payload = vec![0u8; usize::from(header[2])];
        self.io.read_exact(&mut payload).await?;
        let mt = header[0] >> 5;
        Ok(Packet {
            mt,
            pbf: header[0] & 0x10 != 0,
            gid: header[0] & 0x0F,
            oid: if mt == MT_DATA { 0 } else { header[1] & 0x3F },
            payload,
        })
    }

    async fn write_packet(&mut self, packet: &Packet) -> Result<(), NciError> {
        self.io.write_all(&packet.encode()).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Envoie une commande et attend sa réponse; les autres paquets sont mis de côté.
    async fn command(&mut self, gid: u8, oid: u8, payload: Vec<u8>) -> Result<u8, NciError> {
        self.write_packet(&Packet::control(MT_CMD, gid, oid, payload))
            .await?;
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            let packet = timeout(
                deadline.saturating_duration_since(Instant::now()),
                self.read_packet(),
            )
            .await
            .map_err(|_| NciError::Timeout)??;
            if packet.is(MT_RSP, gid, oid) {
                return packet.payload.first().copied().ok_or(NciError::Malformed);
            }
            self.pending.push_back(packet);
        }
    }

    async fn command_ok(&mut self, gid: u8, oid: u8, payload: Vec<u8>) -> Result<(), NciError> {
        match self.command(gid, oid, payload).await? {
            STATUS_OK => Ok(()),
            status => Err(NciError::Status { gid, oid, status }),
        }
    }

    /// Prochain paquet (mis de côté ou lu), avec délai.
    async fn next_packet(&mut self, wait: Duration) -> Result<Packet, NciError> {
        if let Some(packet) = self.pending.pop_front() {
            return Ok(packet);
        }
        timeout(wait, self.read_packet())
            .await
            .map_err(|_| NciError::Timeout)?
    }

    /// Désactive le RF (`type_` : repos ou retour en découverte) et attend la
    /// notification correspondante si le contrôleur en envoie une.
    async fn deactivate(&mut self, type_: u8) -> Result<(), NciError> {
        match self.command(GID_RF, OID_RF_DEACTIVATE, vec![type_]).await? {
            // Déjà au repos : rien à attendre.
            STATUS_SEMANTIC_ERROR if type_ == DEACTIVATE_IDLE => return Ok(()),
            STATUS_OK => {}
            status => {
                return Err(NciError::Status {
                    gid: GID_RF,
                    oid: OID_RF_DEACTIVATE,
                    status,
                });
            }
        }
        self.active = false;
        // Les autres paquets reçus entre-temps sont conservés pour la suite.
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut others = Vec::new();
        while let Ok(packet) = self
            .next_packet(deadline.saturating_duration_since(Instant::now()))
            .await
        {
            if packet.is(MT_NTF, GID_RF, OID_RF_DEACTIVATE) {
                break;
            }
            others.push(packet);
        }
        for packet in others.into_iter().rev() {
            self.pending.push_front(packet);
        }
        Ok(())
    }

    /// Lance la découverte NFC-A en mode lecteur et attend l'activation d'une
    /// carte ISO-DEP. Les cartes d'un autre type (simples étiquettes) sont
    /// ignorées. `cancelled` est consulté au moins deux fois par seconde.
    pub async fn activate_iso_dep(
        &mut self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Activation, NciError> {
        self.deactivate(DEACTIVATE_IDLE).await?;
        // ISO-DEP en mode lecteur → interface ISO-DEP (le contrôleur gère les blocs I/R/S).
        self.command_ok(
            GID_RF,
            OID_RF_DISCOVER_MAP,
            vec![1, PROTOCOL_ISO_DEP, MODE_POLL, INTERFACE_ISO_DEP],
        )
        .await?;
        self.command_ok(GID_RF, OID_RF_DISCOVER, vec![1, TECH_NFC_A_PASSIVE_POLL, 1])
            .await?;

        let mut discovered: Vec<(u8, u8)> = Vec::new();
        loop {
            if cancelled() {
                let _ = self.deactivate(DEACTIVATE_IDLE).await;
                return Err(NciError::Cancelled);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let _ = self.deactivate(DEACTIVATE_IDLE).await;
                return Err(NciError::Timeout);
            }
            let packet = match self
                .next_packet(remaining.min(Duration::from_millis(500)))
                .await
            {
                Err(NciError::Timeout) => continue,
                other => other?,
            };
            if packet.is(MT_NTF, GID_RF, OID_RF_INTF_ACTIVATED) {
                let p = &packet.payload;
                if p.len() < 6 {
                    return Err(NciError::Malformed);
                }
                let activation = Activation {
                    discovery_id: p[0],
                    interface: p[1],
                    protocol: p[2],
                    max_payload: p[4],
                    credits: p[5],
                };
                if activation.protocol == PROTOCOL_ISO_DEP
                    && activation.interface == INTERFACE_ISO_DEP
                {
                    self.max_payload = usize::from(activation.max_payload.max(1));
                    self.credits = activation.credits;
                    self.active = true;
                    return Ok(activation);
                }
                // Étiquette sans ISO-DEP : on reprend la découverte.
                self.deactivate(DEACTIVATE_DISCOVERY).await?;
                discovered.clear();
            } else if packet.is(MT_NTF, GID_RF, OID_RF_DISCOVER) {
                // Plusieurs cartes dans le champ : on choisit la première ISO-DEP.
                let p = &packet.payload;
                if p.len() < 3 {
                    return Err(NciError::Malformed);
                }
                discovered.push((p[0], p[1]));
                let more = p.last() == Some(&2);
                if !more {
                    if let Some(&(id, _)) = discovered
                        .iter()
                        .find(|(_, proto)| *proto == PROTOCOL_ISO_DEP)
                    {
                        self.command_ok(
                            GID_RF,
                            OID_RF_DISCOVER_SELECT,
                            vec![id, PROTOCOL_ISO_DEP, INTERFACE_ISO_DEP],
                        )
                        .await?;
                    } else {
                        self.deactivate(DEACTIVATE_DISCOVERY).await?;
                    }
                    discovered.clear();
                }
            }
            // Autres notifications (erreurs génériques, etc.) : ignorées ici.
        }
    }

    /// Envoie un APDU sur l'interface ISO-DEP et retourne l'APDU de réponse.
    pub async fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, NciError> {
        if !self.active {
            return Err(NciError::TagLost);
        }
        let chunks: Vec<&[u8]> = if apdu.is_empty() {
            vec![&[][..]]
        } else {
            apdu.chunks(self.max_payload).collect()
        };
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.into_iter().enumerate() {
            while self.credits == 0 {
                let packet = self.next_packet(DATA_TIMEOUT).await?;
                self.handle_side_packet(&packet)?;
            }
            self.write_packet(&Packet {
                mt: MT_DATA,
                pbf: i != last,
                gid: STATIC_RF_CONN,
                oid: 0,
                payload: chunk.to_vec(),
            })
            .await?;
            if self.credits != CREDITS_UNLIMITED {
                self.credits -= 1;
            }
        }

        let mut response = Vec::new();
        let deadline = Instant::now() + DATA_TIMEOUT;
        loop {
            let packet = self
                .next_packet(deadline.saturating_duration_since(Instant::now()))
                .await?;
            if packet.mt == MT_DATA && packet.gid == STATIC_RF_CONN {
                response.extend_from_slice(&packet.payload);
                if !packet.pbf {
                    return Ok(response);
                }
            } else {
                self.handle_side_packet(&packet)?;
            }
        }
    }

    /// Crédits, erreurs et désactivations reçus pendant un échange de données.
    fn handle_side_packet(&mut self, packet: &Packet) -> Result<(), NciError> {
        if packet.is(MT_NTF, GID_CORE, OID_CORE_CONN_CREDITS) {
            let p = &packet.payload;
            let entries = usize::from(*p.first().ok_or(NciError::Malformed)?);
            for entry in p[1..].chunks(2).take(entries) {
                if let [conn, credits] = *entry
                    && conn == STATIC_RF_CONN
                    && self.credits != CREDITS_UNLIMITED
                {
                    self.credits = self.credits.saturating_add(credits);
                }
            }
        } else if packet.is(MT_NTF, GID_CORE, OID_CORE_INTERFACE_ERROR) {
            self.active = false;
            return Err(NciError::Interface(
                packet.payload.first().copied().unwrap_or(0xFF),
            ));
        } else if packet.is(MT_NTF, GID_RF, OID_RF_DEACTIVATE) {
            self.active = false;
            return Err(NciError::TagLost);
        } else if packet.is(MT_NTF, GID_CORE, OID_CORE_GENERIC_ERROR) {
            eprintln!("erreur NCI générique : {:02x?}", packet.payload);
        }
        Ok(())
    }
}

// ----- CTAP sur NFC (CTAP 2.1, §11.3) -----

/// AID de l'applet FIDO.
const FIDO_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
const APPLET_FIDO_2_0: &[u8] = b"FIDO_2_0";
const APPLET_U2F_V2: &[u8] = b"U2F_V2";
const CLA_CTAP: u8 = 0x80;
const CLA_CHAINING: u8 = 0x10;
const INS_NFCCTAP_MSG: u8 = 0x10;
const INS_NFCCTAP_GETRESPONSE: u8 = 0x11;
const INS_GET_RESPONSE: u8 = 0xC0;
/// Nombre maximal d'attentes `9100` (environ 30 s à 100 ms chacune).
const MAX_KEEPALIVES: usize = 300;

/// APDU court ISO 7816-4.
fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
    let mut out = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    if let Some(le) = le {
        out.push(le);
    }
    out
}

/// Sépare un APDU de réponse en (données, SW1, SW2).
fn split_response(mut response: Vec<u8>) -> Result<(Vec<u8>, u8, u8), NciError> {
    if response.len() < 2 {
        return Err(NciError::Malformed);
    }
    let sw2 = response.pop().unwrap_or_default();
    let sw1 = response.pop().unwrap_or_default();
    Ok((response, sw1, sw2))
}

/// Clé FIDO2 présentée à la puce NFC intégrée.
pub struct NciToken<S> {
    nci: Nci<S>,
    selected: bool,
}

impl<S> fmt::Debug for NciToken<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NciToken")
            .field("nci", &self.nci)
            .field("selected", &self.selected)
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> NciToken<S> {
    /// `nci` doit avoir une interface ISO-DEP active.
    pub fn new(nci: Nci<S>) -> Self {
        Self {
            nci,
            selected: false,
        }
    }

    /// Envoie un APDU et rassemble la réponse complète (`61xx` → GET RESPONSE).
    async fn exchange(&mut self, command: &[u8]) -> Result<(Vec<u8>, u8, u8), NciError> {
        let (mut data, mut sw1, mut sw2) = split_response(self.nci.transceive(command).await?)?;
        while sw1 == 0x61 {
            let (more, s1, s2) = split_response(
                self.nci
                    .transceive(&apdu(0x00, INS_GET_RESPONSE, 0, 0, &[], Some(sw2)))
                    .await?,
            )?;
            data.extend_from_slice(&more);
            (sw1, sw2) = (s1, s2);
        }
        Ok((data, sw1, sw2))
    }

    async fn select_applet(&mut self) -> Result<Vec<u8>, NciError> {
        let (data, sw1, sw2) = self
            .exchange(&apdu(0x00, 0xA4, 0x04, 0x00, &FIDO_AID, Some(0)))
            .await?;
        if (sw1, sw2) != (0x90, 0x00) {
            return Err(NciError::Status {
                gid: 0xA4,
                oid: 0,
                status: sw1,
            });
        }
        Ok(data)
    }
}

#[async_trait]
impl<S> Token for NciToken<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    type Id = ();

    fn has_button(&self) -> bool {
        // En NFC, poser la clé vaut présence de l'utilisateur.
        false
    }

    fn get_transport(&self) -> AuthenticatorTransport {
        AuthenticatorTransport::Nfc
    }

    async fn transmit_raw<U>(&mut self, cbor: &[u8], ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback,
    {
        if !self.selected {
            return Err(WebauthnCError::Internal);
        }
        // Chaînage de commandes : fragments de 255 octets, CLA 0x90 sauf le dernier.
        let chunks: Vec<&[u8]> = if cbor.is_empty() {
            vec![&[][..]]
        } else {
            cbor.chunks(255).collect()
        };
        let last = chunks.len() - 1;
        let mut response = None;
        for (i, chunk) in chunks.into_iter().enumerate() {
            let (cla, le) = if i == last {
                (CLA_CTAP, Some(0))
            } else {
                (CLA_CTAP | CLA_CHAINING, None)
            };
            let (data, sw1, sw2) = self
                .exchange(&apdu(cla, INS_NFCCTAP_MSG, 0, 0, chunk, le))
                .await?;
            if i != last && (sw1, sw2) != (0x90, 0x00) {
                return Err(WebauthnCError::ApduTransmission);
            }
            response = Some((data, sw1, sw2));
        }
        let (mut data, mut sw1, mut sw2) = response.ok_or(WebauthnCError::Internal)?;

        // 9100 : la clé travaille encore; on interroge avec NFCCTAP_GETRESPONSE.
        let mut keepalives = 0;
        while (sw1, sw2) == (0x91, 0x00) {
            keepalives += 1;
            if keepalives > MAX_KEEPALIVES {
                return Err(WebauthnCError::Ctap(CtapError::Ctap2ActionTimeout));
            }
            ui.processing();
            tokio::time::sleep(Duration::from_millis(100)).await;
            (data, sw1, sw2) = self
                .exchange(&apdu(CLA_CTAP, INS_NFCCTAP_GETRESPONSE, 0, 0, &[], Some(0)))
                .await?;
        }
        if (sw1, sw2) != (0x90, 0x00) {
            eprintln!("réponse CTAP NFC : SW {sw1:02x}{sw2:02x}");
            return Err(WebauthnCError::ApduTransmission);
        }
        if data.is_empty() {
            return Err(WebauthnCError::Cbor);
        }
        let status = CtapError::from(data.remove(0));
        if !status.is_ok() {
            return Err(status.into());
        }
        Ok(data)
    }

    async fn cancel(&mut self) -> Result<(), WebauthnCError> {
        // CTAP sur NFC n'a pas de commande d'annulation.
        Ok(())
    }

    async fn init(&mut self) -> Result<(), WebauthnCError> {
        let version = self.select_applet().await?;
        if version != APPLET_FIDO_2_0 && version != APPLET_U2F_V2 {
            eprintln!("applet FIDO inattendu : {version:02x?}");
            return Err(WebauthnCError::NotSupported);
        }
        self.selected = true;
        Ok(())
    }

    async fn close(&mut self) -> Result<(), WebauthnCError> {
        self.selected = false;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! Contrôleur NFC simulé : répond aux commandes NCI utilisées, active une
    //! carte ISO-DEP (après une étiquette sans ISO-DEP) et y héberge un applet
    //! FIDO simulé. Petite taille de paquet et crédits comptés pour exercer la
    //! fragmentation et le contrôle de flux.

    use super::*;

    /// Réponse GetInfo réelle d'une YubiKey 5 NFC (tests de webauthn-authenticator-rs).
    pub const YUBIKEY_GET_INFO: &[u8] = &[
        170, 1, 131, 102, 85, 50, 70, 95, 86, 50, 104, 70, 73, 68, 79, 95, 50, 95, 48, 108, 70, 73,
        68, 79, 95, 50, 95, 49, 95, 80, 82, 69, 2, 130, 107, 99, 114, 101, 100, 80, 114, 111, 116,
        101, 99, 116, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 3, 80, 47, 192, 87,
        159, 129, 19, 71, 234, 177, 22, 187, 90, 141, 185, 32, 42, 4, 165, 98, 114, 107, 245, 98,
        117, 112, 245, 100, 112, 108, 97, 116, 244, 105, 99, 108, 105, 101, 110, 116, 80, 105, 110,
        245, 117, 99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 77, 103, 109, 116, 80, 114, 101,
        118, 105, 101, 119, 245, 5, 25, 4, 176, 6, 129, 1, 7, 8, 8, 24, 128, 9, 130, 99, 110, 102,
        99, 99, 117, 115, 98, 10, 130, 162, 99, 97, 108, 103, 38, 100, 116, 121, 112, 101, 106,
        112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 39, 100, 116, 121,
        112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121,
    ];

    /// GetInfo de la YubiKey, mais sans NIP configuré (`clientPin: false`),
    /// pour que l'assertion ne passe pas par authenticatorClientPIN.
    fn get_info_without_pin() -> Vec<u8> {
        let mut info = YUBIKEY_GET_INFO.to_vec();
        let key = b"iclientPin"; // chaîne CBOR de 9 caractères (0x69)
        let at = info
            .windows(key.len())
            .position(|w| w == key)
            .expect("clé clientPin");
        let value = at + key.len();
        assert_eq!(info[value], 0xF5, "clientPin: true");
        info[value] = 0xF4;
        info
    }

    /// Taille maximale des paquets de données du contrôleur simulé.
    const SIM_MAX_PAYLOAD: u8 = 8;

    #[derive(Default)]
    pub struct Stats {
        pub apdus: Vec<Vec<u8>>,
        pub max_data_packet: usize,
        pub keepalives_sent: usize,
    }

    /// Applet FIDO simulé : SELECT, NFCCTAP_MSG (GetInfo), chaînage, 61xx et 9100.
    struct Applet {
        selected: bool,
        chained: Vec<u8>,
        pending_out: Vec<u8>,
        keepalives: usize,
        /// Clé protégée par NIP, qui quitte le champ juste après sa saisie.
        pin_then_lost: bool,
        /// La clé a quitté le champ.
        lost: bool,
    }

    /// Point générateur de P-256 : clé publique d'accord de clé valide.
    const P256_GX: [u8; 32] = [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
        0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98,
        0xC2, 0x96,
    ];
    const P256_GY: [u8; 32] = [
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
        0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF,
        0x51, 0xF5,
    ];

    /// Réponse à authenticatorClientPIN pour une clé à NIP (`None` : clé perdue).
    fn client_pin_reply(command: &[u8]) -> Option<Vec<u8>> {
        // {1: protocole, 2: sous-commande, …}
        match command.get(5) {
            // getKeyAgreement : {1: COSE_Key EC2 P-256}
            Some(0x02) => Some(
                [
                    &[
                        0x00, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21,
                        0x58, 0x20,
                    ][..],
                    &P256_GX,
                    &[0x22, 0x58, 0x20],
                    &P256_GY,
                ]
                .concat(),
            ),
            // getPinRetries : {3: 8}
            Some(0x01) => Some(vec![0x00, 0xA1, 0x03, 0x08]),
            // Demande du jeton NIP : la clé a quitté le champ entre-temps.
            _ => None,
        }
    }

    impl Applet {
        fn respond(&mut self, apdu: &[u8], stats: &mut Stats) -> Vec<u8> {
            stats.apdus.push(apdu.to_vec());
            let (cla, ins) = (apdu[0], apdu[1]);
            let data = if apdu.len() > 5 {
                &apdu[5..5 + usize::from(apdu[4])]
            } else {
                &[][..]
            };
            match ins {
                0xA4 if data == FIDO_AID => {
                    self.selected = true;
                    [APPLET_FIDO_2_0, &[0x90, 0x00]].concat()
                }
                0xA4 => vec![0x6A, 0x82],
                INS_NFCCTAP_MSG if self.selected => {
                    self.chained.extend_from_slice(data);
                    if cla & CLA_CHAINING != 0 {
                        return vec![0x90, 0x00];
                    }
                    let command = std::mem::take(&mut self.chained);
                    if self.pin_then_lost && command.first() == Some(&0x06) {
                        return match client_pin_reply(&command) {
                            Some(reply) => [reply, vec![0x90, 0x00]].concat(),
                            None => {
                                self.lost = true;
                                Vec::new()
                            }
                        };
                    }
                    self.pending_out = match command.first() {
                        // authenticatorGetInfo (NIP configuré ou non)
                        Some(0x04) if self.pin_then_lost => {
                            [&[0x00][..], YUBIKEY_GET_INFO].concat()
                        }
                        Some(0x04) => [&[0x00][..], &get_info_without_pin()].concat(),
                        // authenticatorGetAssertion : aucun identifiant connu.
                        Some(0x02) => vec![0x2E],
                        // Autres commandes : CTAP1_ERR_INVALID_COMMAND.
                        _ => vec![0x01],
                    };
                    // La clé « travaille » deux fois avant de répondre.
                    self.keepalives = 2;
                    vec![0x91, 0x00]
                }
                INS_NFCCTAP_GETRESPONSE if self.keepalives > 0 => {
                    self.keepalives -= 1;
                    stats.keepalives_sent += 1;
                    vec![0x91, 0x00]
                }
                INS_NFCCTAP_GETRESPONSE | INS_GET_RESPONSE => {
                    // Réponse par morceaux de 64 octets (61xx pour la suite).
                    let n = self.pending_out.len().min(64);
                    let mut out: Vec<u8> = self.pending_out.drain(..n).collect();
                    match self.pending_out.len() {
                        0 => out.extend([0x90, 0x00]),
                        left => out.extend([0x61, left.min(255) as u8]),
                    }
                    out
                }
                _ => vec![0x6D, 0x00],
            }
        }
    }

    /// Joue le rôle du démon + contrôleur de l'autre côté du socket.
    pub async fn run_controller<S: AsyncRead + AsyncWrite + Unpin>(
        mut io: S,
        stats: std::sync::Arc<std::sync::Mutex<Stats>>,
        pin_then_lost: bool,
    ) {
        let mut nci = Nci::new(&mut io);
        let mut applet = Applet {
            selected: false,
            chained: Vec::new(),
            pending_out: Vec::new(),
            keepalives: 0,
            pin_then_lost,
            lost: false,
        };
        let mut discovering = false;
        let mut tag_shown = false;
        let mut rx = Vec::new();
        loop {
            let Ok(packet) = nci.read_packet().await else {
                return;
            };
            match (packet.mt, packet.gid, packet.oid) {
                (MT_CMD, GID_RF, OID_RF_DEACTIVATE) => {
                    let was_active = discovering;
                    let status = if was_active {
                        STATUS_OK
                    } else {
                        STATUS_SEMANTIC_ERROR
                    };
                    nci.write_packet(&Packet::control(
                        MT_RSP,
                        GID_RF,
                        OID_RF_DEACTIVATE,
                        vec![status],
                    ))
                    .await
                    .unwrap();
                    if was_active {
                        nci.write_packet(&Packet::control(
                            MT_NTF,
                            GID_RF,
                            OID_RF_DEACTIVATE,
                            vec![packet.payload[0], 0x00],
                        ))
                        .await
                        .unwrap();
                    }
                    discovering = packet.payload[0] == DEACTIVATE_DISCOVERY;
                    if discovering {
                        // Après l'étiquette, la vraie clé FIDO est présentée.
                        activate(&mut nci, PROTOCOL_ISO_DEP, INTERFACE_ISO_DEP).await;
                    }
                }
                (MT_CMD, GID_RF, OID_RF_DISCOVER_MAP) => {
                    assert_eq!(
                        packet.payload,
                        vec![1, PROTOCOL_ISO_DEP, MODE_POLL, INTERFACE_ISO_DEP]
                    );
                    nci.write_packet(&Packet::control(
                        MT_RSP,
                        GID_RF,
                        OID_RF_DISCOVER_MAP,
                        vec![0],
                    ))
                    .await
                    .unwrap();
                }
                (MT_CMD, GID_RF, OID_RF_DISCOVER) => {
                    nci.write_packet(&Packet::control(MT_RSP, GID_RF, OID_RF_DISCOVER, vec![0]))
                        .await
                        .unwrap();
                    discovering = true;
                    if !tag_shown {
                        tag_shown = true;
                        // D'abord une simple étiquette NFC-A (T2T, interface Frame).
                        activate(&mut nci, 0x02, 0x01).await;
                    }
                }
                (MT_DATA, STATIC_RF_CONN, _) => {
                    assert!(packet.payload.len() <= usize::from(SIM_MAX_PAYLOAD));
                    rx.extend_from_slice(&packet.payload);
                    // Un crédit rendu par paquet reçu.
                    let credits =
                        Packet::control(MT_NTF, GID_CORE, OID_CORE_CONN_CREDITS, vec![1, 0, 1]);
                    let reply = {
                        let mut s = stats.lock().unwrap();
                        s.max_data_packet = s.max_data_packet.max(packet.payload.len());
                        if packet.pbf {
                            None
                        } else {
                            Some(applet.respond(&std::mem::take(&mut rx), &mut s))
                        }
                    };
                    nci.write_packet(&credits).await.unwrap();
                    if applet.lost {
                        // Retrait de la clé : désactivation RF signalée, plus de réponse.
                        nci.write_packet(&Packet::control(
                            MT_NTF,
                            GID_RF,
                            OID_RF_DEACTIVATE,
                            vec![DEACTIVATE_DISCOVERY, 0x02],
                        ))
                        .await
                        .unwrap();
                        continue;
                    }
                    if let Some(reply) = reply {
                        let chunks: Vec<&[u8]> =
                            reply.chunks(usize::from(SIM_MAX_PAYLOAD)).collect();
                        let last = chunks.len() - 1;
                        for (i, chunk) in chunks.into_iter().enumerate() {
                            nci.write_packet(&Packet {
                                mt: MT_DATA,
                                pbf: i != last,
                                gid: STATIC_RF_CONN,
                                oid: 0,
                                payload: chunk.to_vec(),
                            })
                            .await
                            .unwrap();
                        }
                    }
                }
                other => panic!("paquet NCI inattendu : {other:?}"),
            }
        }
    }

    async fn activate<S: AsyncRead + AsyncWrite + Unpin>(
        nci: &mut Nci<&mut S>,
        protocol: u8,
        interface: u8,
    ) {
        // Un crédit initial seulement : le contrôle de flux est exercé.
        nci.write_packet(&Packet::control(
            MT_NTF,
            GID_RF,
            OID_RF_INTF_ACTIVATED,
            vec![
                1,
                interface,
                protocol,
                TECH_NFC_A_PASSIVE_POLL,
                SIM_MAX_PAYLOAD,
                1,
                0,
            ],
        ))
        .await
        .unwrap();
    }

    #[test]
    fn encodage_paquets() {
        let cmd = Packet::control(MT_CMD, GID_RF, OID_RF_DEACTIVATE, vec![0]);
        assert_eq!(cmd.encode(), vec![0x21, 0x06, 0x01, 0x00]);
        let data = Packet {
            mt: MT_DATA,
            pbf: true,
            gid: 0,
            oid: 0,
            payload: vec![1, 2],
        };
        assert_eq!(data.encode(), vec![0x10, 0x00, 0x02, 1, 2]);
    }

    #[test]
    fn apdus_courts() {
        assert_eq!(
            apdu(0x00, 0xA4, 0x04, 0x00, &FIDO_AID, Some(0)),
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00
            ]
        );
        assert_eq!(
            apdu(0x80, 0x11, 0, 0, &[], Some(0)),
            vec![0x80, 0x11, 0, 0, 0]
        );
    }

    /// Parcours complet : étiquette ignorée, carte ISO-DEP activée, sélection
    /// de l'applet puis GetInfo CTAP2 via `CtapAuthenticator` (fragmentation
    /// NCI, crédits, chaînage de commandes, 9100 et 61xx).
    #[test]
    fn ctap2_sur_nci_simule() {
        use webauthn_authenticator_rs::ctap2::CtapAuthenticator;

        #[derive(Debug)]
        struct Ui;
        impl UiCallback for Ui {
            fn request_pin(&self) -> Option<String> {
                None
            }
            fn request_touch(&self) {}
            fn processing(&self) {}
            fn fingerprint_enrollment_feedback(
                &self,
                _: u32,
                _: Option<webauthn_authenticator_rs::types::EnrollSampleStatus>,
            ) {
            }
            fn cable_qr_code(
                &self,
                _: webauthn_authenticator_rs::types::CableRequestType,
                _: String,
            ) {
            }
            fn dismiss_qr_code(&self) {}
            fn cable_status_update(&self, _: webauthn_authenticator_rs::types::CableState) {}
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (client, server) = tokio::io::duplex(4096);
            let stats = std::sync::Arc::new(std::sync::Mutex::new(Stats::default()));
            tokio::spawn(run_controller(server, stats.clone(), false));

            let mut nci = Nci::new(client);
            let activation = nci
                .activate_iso_dep(Instant::now() + Duration::from_secs(5), &|| false)
                .await
                .unwrap();
            assert_eq!(activation.protocol, PROTOCOL_ISO_DEP);
            assert_eq!(activation.max_payload, SIM_MAX_PAYLOAD);

            let ui = Ui;
            let authenticator = CtapAuthenticator::new(NciToken::new(nci), &ui)
                .await
                .expect("GetInfo via NCI");
            drop(authenticator);

            let s = stats.lock().unwrap();
            // SELECT de l'applet FIDO, puis NFCCTAP_MSG(GetInfo).
            assert_eq!(s.apdus[0][..5], [0x00, 0xA4, 0x04, 0x00, 0x08]);
            assert_eq!(
                s.apdus[1],
                vec![CLA_CTAP, INS_NFCCTAP_MSG, 0, 0, 1, 0x04, 0x00]
            );
            // 9100 au message, puis deux fois 9100 à NFCCTAP_GETRESPONSE.
            assert_eq!(s.keepalives_sent, 2);
            assert!(s.apdus.iter().any(|a| a[1] == INS_GET_RESPONSE));
            // Le SELECT (14 octets) a dû être fragmenté en paquets de 8 octets.
            assert_eq!(s.max_data_packet, usize::from(SIM_MAX_PAYLOAD));
        });
    }

    /// Un long message CBOR est découpé en APDU chaînés (CLA 0x90).
    #[test]
    fn chainage_des_commandes() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (client, mut server) = tokio::io::duplex(8192);
            let responder = tokio::spawn(async move {
                let mut nci = Nci::new(&mut server);
                let mut apdus = Vec::new();
                let mut rx = Vec::new();
                while apdus.len() < 3 {
                    let packet = nci.read_packet().await.unwrap();
                    rx.extend_from_slice(&packet.payload);
                    if packet.pbf {
                        continue;
                    }
                    let apdu = std::mem::take(&mut rx);
                    let reply = if apdu[0] & CLA_CHAINING != 0 {
                        vec![0x90, 0x00]
                    } else {
                        vec![0x00, 0xA1, 0x90, 0x00]
                    };
                    apdus.push(apdu);
                    nci.write_packet(&Packet {
                        mt: MT_DATA,
                        pbf: false,
                        gid: 0,
                        oid: 0,
                        payload: reply,
                    })
                    .await
                    .unwrap();
                }
                apdus
            });

            let mut nci = Nci::new(client);
            nci.active = true;
            let mut token = NciToken::new(nci);
            token.selected = true;
            #[derive(Debug)]
            struct Ui;
            impl UiCallback for Ui {
                fn request_pin(&self) -> Option<String> {
                    None
                }
                fn request_touch(&self) {}
                fn processing(&self) {}
                fn fingerprint_enrollment_feedback(
                    &self,
                    _: u32,
                    _: Option<webauthn_authenticator_rs::types::EnrollSampleStatus>,
                ) {
                }
                fn cable_qr_code(
                    &self,
                    _: webauthn_authenticator_rs::types::CableRequestType,
                    _: String,
                ) {
                }
                fn dismiss_qr_code(&self) {}
                fn cable_status_update(&self, _: webauthn_authenticator_rs::types::CableState) {}
            }
            let cbor = vec![0x42; 600];
            let response = token.transmit_raw(&cbor, &Ui).await.unwrap();
            assert_eq!(response, vec![0xA1]);
            let apdus = responder.await.unwrap();
            assert_eq!(apdus.len(), 3);
            assert_eq!(apdus[0][0], CLA_CTAP | CLA_CHAINING);
            assert_eq!(apdus[0][4], 255);
            assert_eq!(apdus[1][0], CLA_CTAP | CLA_CHAINING);
            assert_eq!(apdus[2][0], CLA_CTAP);
            assert_eq!(usize::from(apdus[2][4]), 600 - 2 * 255);
            assert_eq!(*apdus[2].last().unwrap(), 0x00, "Le = 256");
        });
    }
}
