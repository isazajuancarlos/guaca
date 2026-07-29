// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Juan Carlos Isaza Arenas
//! Cifrado autenticado **en reposo**. Envuelve bytes en un contenedor cifrado de
//! Quipu: KDF (Argon2) sobre la frase → AEAD → padding Padmé que oculta la
//! longitud real. Para archivos en disco (imágenes de paciente, entregas) y blobs
//! sensibles de la base.
//!
//! El mismo `blob` que devuelve [`cifrar`] se guarda y luego se descifra con la
//! MISMA frase. La frase la deriva el despliegue (de un secreto de entorno, o
//! repartida con Shamir para respaldo); **nunca se guarda junto al blob** —si
//! están juntos, el cifrado no protege de nada—.
//!
//! Un blob alterado un solo bit no descifra: el AEAD lo detecta y [`descifrar`]
//! devuelve `Err`. Así el cifrado da, de paso, integridad.

use quipu::api::{decode_from_blob, encode_to_blob, DecodeError, Options};
// El trait `HuellaDeCodebook` aporta `.fingerprint()` sobre `Dictionary`; tiene
// que estar en scope aquí, donde se llama.
use quipu::dictionary::HuellaDeCodebook;

use crate::dict;

/// Cifra `datos` con `frase`. Devuelve el blob a persistir (cabecera + ciphertext
/// + sal + nonce; todo lo necesario para descifrar menos la frase).
pub fn cifrar(datos: &[u8], frase: &str) -> Vec<u8> {
    encode_to_blob(datos, frase, dict().fingerprint(), &Options::default())
}

/// Descifra un blob producido por [`cifrar`]. `Err` si la frase no corresponde o
/// si el blob fue alterado tras cifrarse.
pub fn descifrar(blob: &[u8], frase: &str) -> Result<Vec<u8>, DecodeError> {
    // `pepper` vacío para casar con `Options::default()`, que usa `b""`.
    decode_from_blob(blob, frase, dict().fingerprint(), b"")
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn ida_y_vuelta() {
        let secreto = b"radiografia de torax del paciente 42";
        let blob = cifrar(secreto, "frase-del-despliegue-larga-y-propia");
        // El blob NO contiene el plaintext en claro.
        assert!(!blob.windows(secreto.len()).any(|w| w == secreto));
        let claro = descifrar(&blob, "frase-del-despliegue-larga-y-propia").unwrap();
        assert_eq!(claro, secreto);
    }

    #[test]
    fn la_frase_equivocada_no_descifra() {
        let blob = cifrar(b"dato", "frase-correcta-de-mas-de-treinta-bytes");
        assert!(descifrar(&blob, "frase-incorrecta").is_err());
    }

    #[test]
    fn un_blob_alterado_no_descifra() {
        let mut blob = cifrar(b"dato sensible", "una-frase-cualquiera-larga-1234");
        // Voltear un byte del ciphertext: el AEAD debe rechazarlo.
        let n = blob.len();
        blob[n - 1] ^= 0x01;
        assert!(descifrar(&blob, "una-frase-cualquiera-larga-1234").is_err());
    }

    #[test]
    fn dos_cifrados_del_mismo_dato_difieren() {
        // Sal y nonce aleatorios: dos blobs del mismo dato no son iguales (no se
        // puede saber que dos archivos guardan lo mismo mirando el ciphertext).
        let a = cifrar(b"igual", "misma-frase-de-mas-de-treinta-bytes-xx");
        let b = cifrar(b"igual", "misma-frase-de-mas-de-treinta-bytes-xx");
        assert_ne!(a, b);
    }
}
