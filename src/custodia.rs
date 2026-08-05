// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Juan Carlos Isaza Arenas
//! Custodia de claves: **derivar** una clave de un secreto de despliegue y
//! **repartirla** para respaldo, de modo que ningún sitio único la tenga entera.
//!
//! Cierra el hueco de tener la clave de firma/cifrado en el entorno: en vez de
//! guardar la clave cruda, se deriva de un secreto ([`derivar`]) y se respalda
//! partida en comparticiones 2-de-3 ([`repartir`] / [`recuperar`]), como el seed
//! del OPRF. Shamir es informacionalmente seguro: con menos del umbral no se
//! aprende NADA del secreto.
//!
//! Es para **respaldo**, no para firma rutinaria: no se convoca a los custodios
//! en cada operación. La firma en línea usa la clave del entorno; esto la
//! recupera si el entorno se pierde.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use quipu::kdf::{self, KdfParams};
use quipu::shamir::{self, Share, ShamirError};
use zeroize::Zeroizing;

/// Longitud del salt de derivación (128 bits), la de Quipu.
pub const SAL_LEN: usize = kdf::SALT_LEN;

/// Errores de custodia. No dicen más de lo necesario: una compartición corrupta
/// no revela cuál, ni la reconstrucción qué le faltó.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodiaError {
    /// Umbral < 2, total < umbral, total > 255, o secreto vacío.
    Parametros,
    /// Una compartición no es texto/bytes válidos.
    Comparticion,
    /// Faltan comparticiones, no son del mismo reparto, o alguna está corrupta.
    Reconstruccion,
    /// El sistema no entregó aleatoriedad. **No se repartió nada**: un reparto
    /// con coeficientes predecibles se reconstruye con menos comparticiones de
    /// las que dice el umbral. Fallar ruidosamente, nunca rellenar.
    SinEntropia,
}

impl std::fmt::Display for CustodiaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parametros => write!(f, "parámetros de reparto inválidos"),
            Self::Comparticion => write!(f, "una compartición no es válida"),
            Self::Reconstruccion => write!(f, "no se pudo reconstruir el secreto"),
            Self::SinEntropia => write!(f, "el sistema no entregó aleatoriedad"),
        }
    }
}

impl std::error::Error for CustodiaError {}

fn de_shamir(e: ShamirError) -> CustodiaError {
    match e {
        ShamirError::BadParameters | ShamirError::EmptySecret => CustodiaError::Parametros,
        ShamirError::Malformed => CustodiaError::Comparticion,
        ShamirError::SinEntropia(_) => CustodiaError::SinEntropia,
        ShamirError::NotEnoughShares { .. }
        | ShamirError::Inconsistent
        | ShamirError::VerificationFailed => CustodiaError::Reconstruccion,
    }
}

/// Deriva una clave uniforme de 32 bytes de un secreto de despliegue humano y un
/// salt. Argon2id (memory-hard) con el coste de referencia: es una derivación de
/// arranque, no por petición, así que el coste alto está bien. El MISMO secreto y
/// salt dan siempre la MISMA clave; guarde el salt junto al despliegue (no es
/// secreto), y el secreto aparte.
pub fn derivar(secreto: &str, sal: &[u8; SAL_LEN]) -> [u8; kdf::KEY_LEN] {
    kdf::derive_master_key(secreto, sal, b"", &KdfParams::default())
}

/// Un salt nuevo. Falla ruidosamente si no hay entropía: un salt predecible
/// abarata el ataque por diccionario contra el secreto.
pub fn sal_nueva() -> Result<[u8; SAL_LEN], CustodiaError> {
    let mut sal = [0u8; SAL_LEN];
    quipu::aleatorio::llenar(&mut sal).map_err(|_| CustodiaError::SinEntropia)?;
    Ok(sal)
}

/// Parte `secreto` en `total` comparticiones, de las que `umbral` bastan para
/// recuperarlo. Cada compartición sale como texto portable (base64 url-safe) para
/// escribirla en papel o llevarla en un USB. Reparto de referencia: 2-de-3.
pub fn repartir(secreto: &[u8], umbral: u8, total: u8) -> Result<Vec<String>, CustodiaError> {
    let shares = shamir::split(secreto, umbral, total).map_err(de_shamir)?;
    Ok(shares
        .iter()
        .map(|s| URL_SAFE_NO_PAD.encode(s.to_bytes()))
        .collect())
}

/// Reconstruye el secreto a partir de al menos `umbral` comparticiones. Devuelto
/// zeroizing: se borra de memoria al soltarlo. Falla —sin decir cuál— si alguna
/// está corrupta o si no llegan suficientes.
pub fn recuperar(comparticiones: &[String]) -> Result<Zeroizing<Vec<u8>>, CustodiaError> {
    let mut shares = Vec::with_capacity(comparticiones.len());
    for c in comparticiones {
        let bytes = URL_SAFE_NO_PAD
            .decode(c.trim())
            .map_err(|_| CustodiaError::Comparticion)?;
        shares.push(Share::from_bytes(&bytes).map_err(de_shamir)?);
    }
    shamir::combine(&shares).map_err(de_shamir)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_derivacion_es_determinista() {
        let sal = [7u8; SAL_LEN];
        let a = derivar("secreto-de-despliegue-largo", &sal);
        let b = derivar("secreto-de-despliegue-largo", &sal);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn distinto_salt_da_distinta_clave() {
        let a = derivar("mismo secreto", &[1u8; SAL_LEN]);
        let b = derivar("mismo secreto", &[2u8; SAL_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn dos_de_tres_reconstruye_con_cualquier_par() {
        let secreto = b"la clave privada de firma en hex";
        let partes = repartir(secreto, 2, 3).unwrap();
        assert_eq!(partes.len(), 3);
        for (i, j) in [(0, 1), (0, 2), (1, 2)] {
            let sub = vec![partes[i].clone(), partes[j].clone()];
            assert_eq!(&recuperar(&sub).unwrap()[..], secreto, "el par ({i},{j}) debía recuperar");
        }
    }

    #[test]
    fn una_sola_comparticion_no_basta() {
        let partes = repartir(b"secreto", 2, 3).unwrap();
        assert_eq!(recuperar(&partes[..1]), Err(CustodiaError::Reconstruccion));
    }

    #[test]
    fn una_comparticion_corrupta_no_reconstruye() {
        let secreto = b"secreto que no debe salir mal";
        let mut partes = repartir(secreto, 2, 3).unwrap();
        // Voltear un carácter de la primera compartición.
        let mut bytes = URL_SAFE_NO_PAD.decode(&partes[0]).unwrap();
        let ultimo = bytes.len() - 1;
        bytes[ultimo] ^= 0x01;
        partes[0] = URL_SAFE_NO_PAD.encode(&bytes);
        assert_eq!(
            recuperar(&[partes[0].clone(), partes[1].clone()]),
            Err(CustodiaError::Reconstruccion)
        );
    }

    #[test]
    fn parametros_invalidos_se_rechazan() {
        assert_eq!(repartir(b"x", 1, 3), Err(CustodiaError::Parametros)); // umbral < 2
        assert_eq!(repartir(b"x", 4, 3), Err(CustodiaError::Parametros)); // total < umbral
        assert_eq!(repartir(b"", 2, 3), Err(CustodiaError::Parametros)); // secreto vacío
    }

    #[test]
    fn una_comparticion_ilegible_se_rechaza() {
        assert_eq!(recuperar(&["no es base64 válido !!!".to_string()]), Err(CustodiaError::Comparticion));
    }

    /// Dos comparticiones REALES generadas el 2026-08-04 con guaca 0.4.0, pegadas
    /// aquí como literales. No se regeneran: ese es el punto.
    const PARTE_A: &str = "UVNTMgIBAAAAKBvrrUL5oZOf9FtPDQG8Y1vZ5JNmJy9Gv2NGCT92m_fLBSqxIIK8lXM";
    const PARTE_B: &str = "UVNTMgICAAAAKIJuISFd-qeKkyYIoZjAahXJf5Ks5OUa0mXsvcyMlVoFwE-HH1BS1qM";
    const SECRETO_REPARTIDO: &[u8] = b"la clave privada de firma en hex";

    /// **El vector fijo, y por qué las de arriba no bastan.**
    ///
    /// Una compartición se escribe EN PAPEL —lo dice el módulo— y tiene que seguir
    /// leyéndose dentro de años, con la versión de `base64` que haya entonces.
    /// Todas las demás pruebas de aquí codifican y decodifican con el MISMO
    /// binario, así que pasarían igual aunque el alfabeto cambiara: miden el
    /// códec contra sí mismo. Esta compara contra un artefacto que ya existía.
    ///
    /// Si se pone roja al subir `base64` o `quipu`, NO se regenera el literal:
    /// significa que las comparticiones repartidas hasta hoy dejaron de servir, y
    /// eso es una rotura de compatibilidad que se decide, no se tapa.
    #[test]
    fn una_comparticion_de_2026_sigue_recuperando() {
        let guardadas = vec![PARTE_A.to_string(), PARTE_B.to_string()];
        let recuperado = recuperar(&guardadas).expect("el reparto de 2026-08-04 dejó de leerse");
        assert_eq!(&recuperado[..], SECRETO_REPARTIDO);
    }

    /// La pareja de la anterior, y falla POR LA VÍA REAL: si el alfabeto pasara de
    /// url-safe (`-_`) al estándar (`+/`), esto es exactamente lo que llegaría. No
    /// se voltea un byte al azar —eso solo probaría que la prueba lee el literal—:
    /// se reescribe el MISMO contenido con el otro alfabeto.
    #[test]
    fn con_el_alfabeto_estandar_no_se_lee() {
        use base64::engine::general_purpose::STANDARD;
        let bytes = URL_SAFE_NO_PAD.decode(PARTE_A).unwrap();
        let en_estandar = STANDARD.encode(&bytes);
        assert_ne!(en_estandar, PARTE_A, "el vector no distingue los dos alfabetos: elige otro");
        assert_eq!(
            recuperar(&[en_estandar, PARTE_B.to_string()]),
            Err(CustodiaError::Comparticion),
            "aceptó el alfabeto estándar: el formato en papel no está atado"
        );
    }

    /// Directiva #8: sobre 100+ secretos, 3-de-5 discrimina — todo subconjunto de
    /// tamaño >= umbral reconstruye, todo subconjunto menor falla.
    #[test]
    fn simulacion_umbral_discrimina() {
        for n in 0..110u32 {
            let secreto = format!("secreto-numero-{n}-con-longitud-variable{}", "x".repeat((n % 7) as usize));
            let partes = repartir(secreto.as_bytes(), 3, 5).unwrap();

            // 3 comparticiones (>= umbral) reconstruyen.
            let tres = partes[..3].to_vec();
            assert_eq!(&recuperar(&tres).unwrap()[..], secreto.as_bytes());

            // 2 comparticiones (< umbral) fallan.
            let dos = partes[..2].to_vec();
            assert_eq!(recuperar(&dos), Err(CustodiaError::Reconstruccion));
        }
    }
}
