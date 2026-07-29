// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Juan Carlos Isaza Arenas
//! # guaca
//!
//! _Una guaca es un tesoro enterrado y protegido — aquí, los datos en reposo._
//!
//! Protección en reposo para aplicaciones, sobre [Quipu]: **cifrado autenticado**
//! de archivos y blobs sensibles ([`reposo`]), **firma** de registros con
//! integridad y no repudio post-cuánticos ([`firma`]), **bitácora encadenada** a
//! prueba de manipulación ([`auditoria`]) y **custodia de claves** por KDF +
//! Shamir ([`custodia`]).
//!
//! Nace de una constatación medida: medico e informes copiaban la misma sesión y
//! el mismo endurecimiento de secreto, y las copias YA habían divergido —una
//! mejora de seguridad se quedó en un solo lado—. El código de seguridad
//! duplicado es código de seguridad divergente. Aquí vive una sola vez, se audita
//! una sola vez y se arregla una sola vez.
//!
//! No reimplementa criptografía: es una fachada delgada sobre Quipu, que ya trae
//! el cifrado (`encode_to_blob`) y la firma (`encode_signed`).
//!
//! [Quipu]: https://crates.io/crates/quipu

pub mod auditoria;
pub mod claves;
pub mod custodia;
pub mod firma;
pub mod reposo;
pub mod sesion;

use quipu::dictionary::Dictionary;

/// El alfabeto ASCII imprimible por defecto de Quipu (`0x21..=0x7e`). Debe ser
/// estable: entra en el fingerprint del contenedor cifrado y en la verificación
/// de firmas, así que cambiarlo rompe la compatibilidad con lo ya guardado.
pub(crate) fn dict() -> Dictionary {
    Dictionary::new((0x21u8..=0x7e).map(|b| b as char).collect())
        .expect("el alfabeto ASCII por defecto es válido")
}
