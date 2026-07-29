// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Juan Carlos Isaza Arenas
//! Sesión sin estado en un token firmado: `id|caducidad|firma` (HMAC-SHA256,
//! comparado en tiempo constante). No lleva rol ni permisos —esos se releen de la
//! base en cada petición, porque un rol dentro del token sobrevive a que un
//! administrador lo revoque—.
//!
//! Esto es el TOKEN, no la cookie: guaca no depende de ningún framework web. La
//! app envuelve el valor en `Set-Cookie` (`HttpOnly; SameSite=Strict`, y `Secure`
//! tras el proxy) y lo extrae de la petición.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sesion {
    pub usuario_id: i64,
    pub caduca_en: i64,
}

fn ahora() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn firmar(secreto: &[u8], carga: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secreto).expect("HMAC acepta cualquier longitud");
    mac.update(carga.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// El valor del token para un usuario, válido `minutos` a partir de ahora.
pub fn emitir(secreto: &[u8], usuario_id: i64, minutos: i64) -> String {
    let caduca = ahora() + minutos * 60;
    let carga = format!("{usuario_id}|{caduca}");
    let firma = firmar(secreto, &carga);
    format!("{carga}|{firma}")
}

/// Lee y **verifica**. `None` ante cualquier duda: firma que no cuadra, formato
/// raro o caducado. La caducidad se comprueba EN EL SERVIDOR y va firmada, así que
/// no se puede estirar alterando el token. Un solo `None` para todo: decir cuál
/// falló solo le sirve a quien está probando.
pub fn verificar(secreto: &[u8], valor: &str) -> Option<Sesion> {
    let (carga, firma) = valor.rsplit_once('|')?;
    let esperada = firmar(secreto, carga);
    if !constante_iguales(esperada.as_bytes(), firma.as_bytes()) {
        return None;
    }
    let (id, caduca) = carga.split_once('|')?;
    let sesion = Sesion {
        usuario_id: id.parse().ok()?,
        caduca_en: caduca.parse().ok()?,
    };
    if sesion.caduca_en <= ahora() {
        return None;
    }
    Some(sesion)
}

/// Comparación en tiempo constante: no revela cuántos bytes coincidieron antes de
/// fallar (eso filtraría la firma esperada byte a byte).
fn constante_iguales(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SECRETO: &[u8] = b"un secreto de al menos treinta y dos bytes";

    #[test]
    fn una_sesion_emitida_se_verifica() {
        let v = emitir(SECRETO, 42, 60);
        assert_eq!(verificar(SECRETO, &v).unwrap().usuario_id, 42);
    }

    /// La prueba que discrimina: sin ella, un verificador que siempre devuelve
    /// `Some` pasaría la anterior.
    #[test]
    fn cambiar_el_usuario_invalida_la_firma() {
        let v = emitir(SECRETO, 42, 60);
        let manipulada = v.replacen("42|", "1|", 1);
        assert!(verificar(SECRETO, &manipulada).is_none());
    }

    #[test]
    fn estirar_la_caducidad_invalida_la_firma() {
        let v = emitir(SECRETO, 42, 60);
        let (carga, _) = v.rsplit_once('|').unwrap();
        let (id, caduca) = carga.split_once('|').unwrap();
        let mas_tarde: i64 = caduca.parse::<i64>().unwrap() + 999_999;
        // Reusar la firma vieja con una caducidad nueva no cuela.
        let forjada = format!("{id}|{mas_tarde}|{}", v.rsplit_once('|').unwrap().1);
        assert!(verificar(SECRETO, &forjada).is_none());
    }

    #[test]
    fn otro_secreto_no_vale() {
        let v = emitir(SECRETO, 42, 60);
        assert!(verificar(b"otro secreto igualmente largo de 32+", &v).is_none());
    }

    #[test]
    fn una_sesion_caducada_no_entra() {
        let v = emitir(SECRETO, 42, -1);
        assert!(verificar(SECRETO, &v).is_none());
    }
}
