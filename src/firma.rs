// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Juan Carlos Isaza Arenas
//! Firma de registros: **integridad y no repudio** post-cuánticos (Ed25519 +
//! ML-DSA-87, vía Quipu). Da a un registro una firma que cualquiera con la clave
//! pública puede verificar, y que se rompe si el registro cambia una coma.
//!
//! Firma bytes arbitrarios ([`firmar`]) o, más útil para una fila de base de
//! datos, un mapa de campos en forma canónica y determinista ([`canonico`]): así
//! la firma ata TODOS los campos a la vez.
//!
//! No da confidencialidad —la firma viaja en claro—; para eso está [`crate::reposo`].

use std::collections::BTreeMap;

use quipu::api::{decode_verified, encode_signed};
use quipu::pqsign::{generate_keypair, SigningKey, VerifyingKey};
use serde_json::Value;

use crate::dict;

/// Genera un par de claves: `(clave_publica_hex, clave_privada_hex)`. La segunda
/// es SECRETA: va en un secreto de despliegue o, mejor, en un HSM.
pub fn generar_claves() -> (String, String) {
    let (vk, sk) = generate_keypair();
    (a_hex(&vk.to_bytes()), a_hex(&sk.to_bytes()))
}

/// Firma `datos` con la clave privada (hex). `None` si la clave no es válida.
pub fn firmar(datos: &[u8], clave_privada_hex: &str) -> Option<String> {
    let sk = SigningKey::from_bytes(&de_hex(clave_privada_hex)?)?;
    Some(encode_signed(datos, &sk, &dict()))
}

/// Resultado de verificar. Distingue tres cosas que NO son iguales: la firma vale
/// y el dato está intacto; la firma vale pero el dato cambió tras firmarse; o la
/// firma es inválida/forjada o la clave no sirve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verificacion {
    Valida,
    Alterada,
    Invalida,
}

/// Verifica que `firma` corresponde a `datos` bajo la clave pública (hex).
pub fn verificar(datos: &[u8], firma: &str, clave_publica_hex: &str) -> Verificacion {
    let Some(vk) = de_hex(clave_publica_hex).and_then(|b| VerifyingKey::from_bytes(&b)) else {
        return Verificacion::Invalida;
    };
    match decode_verified(firma, &vk, &dict()) {
        Ok(firmado) if firmado == datos => Verificacion::Valida,
        Ok(_) => Verificacion::Alterada,
        Err(_) => Verificacion::Invalida,
    }
}

/// Forma canónica determinista de un mapa de campos: JSON con claves ORDENADAS y
/// separadores compactos (lo garantiza `BTreeMap` + `serde_json`). Firmar esto ata
/// todos los campos; cambiar cualquiera invalida la firma. Es el mismo esquema que
/// `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`, así que
/// una firma hecha aquí verifica contra la rueda de Python y viceversa.
///
/// Recomendación: incluir siempre una clave de versión (p. ej. `"v": 1`) DENTRO
/// del mapa, para no poder cambiar de esquema sin romper las firmas viejas.
pub fn canonico(campos: &BTreeMap<String, Value>) -> Vec<u8> {
    serde_json::to_vec(campos).expect("un BTreeMap<String, Value> siempre serializa")
}

fn de_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn a_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn campos(estado: &str) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("v".into(), Value::from(1));
        m.insert("id".into(), Value::from(7));
        m.insert("estado".into(), Value::from(estado));
        m
    }

    #[test]
    fn firma_valida_verifica() {
        let (vk, sk) = generar_claves();
        let datos = canonico(&campos("CUMPLIDO"));
        let firma = firmar(&datos, &sk).unwrap();
        assert_eq!(verificar(&datos, &firma, &vk), Verificacion::Valida);
    }

    #[test]
    fn un_cambio_posterior_se_detecta_como_alterada() {
        let (vk, sk) = generar_claves();
        let firma = firmar(&canonico(&campos("CUMPLIDO")), &sk).unwrap();
        // El registro cambió a "INCUMPLIDO" tras firmarse.
        let alterado = canonico(&campos("INCUMPLIDO"));
        assert_eq!(verificar(&alterado, &firma, &vk), Verificacion::Alterada);
    }

    #[test]
    fn otra_clave_no_verifica() {
        let (_, sk) = generar_claves();
        let (otra_vk, _) = generar_claves();
        let datos = canonico(&campos("CUMPLIDO"));
        let firma = firmar(&datos, &sk).unwrap();
        assert_eq!(verificar(&datos, &firma, &otra_vk), Verificacion::Invalida);
    }

    #[test]
    fn clave_privada_invalida_no_firma() {
        assert!(firmar(b"x", "no-es-hex").is_none());
        assert!(firmar(b"x", "abc").is_none()); // longitud impar
    }

    #[test]
    fn clave_publica_invalida_es_invalida() {
        let (_, sk) = generar_claves();
        let firma = firmar(b"x", &sk).unwrap();
        assert_eq!(verificar(b"x", &firma, "zz"), Verificacion::Invalida);
    }

    #[test]
    fn el_canonico_ordena_las_claves() {
        // Insertadas en desorden; el canónico sale igual y con "estado" antes de
        // "id" antes de "v" (orden lexicográfico del BTreeMap).
        let mut a = BTreeMap::new();
        a.insert("v".into(), Value::from(1));
        a.insert("estado".into(), Value::from("X"));
        a.insert("id".into(), Value::from(7));
        assert_eq!(canonico(&a), br#"{"estado":"X","id":7,"v":1}"#);
    }
}
