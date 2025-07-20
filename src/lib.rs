use num_bigint::{BigUint, RandBigInt};
use rand; // For random number generation

pub struct ZKP {
    p: BigUint,
    q: BigUint,
    alpha: BigUint,
    beta: BigUint,
}

impl ZKP {
    //output = n^exp mod p
    pub fn exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        n.modpow(exponent, modulus)
    }
    //output = s = k - c*x mod q
    //k is the prover's random number, c is the challenge, x is the secret, q is the modulus
    //returns s as BigUint

    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        let cx = c * x;
        let k_mod_q = k % &self.q;
        let cx_mod_q = &cx % &self.q;
        if k_mod_q >= cx_mod_q {
            (k_mod_q - cx_mod_q) % &self.q
        } else {
            (&self.q + k_mod_q - cx_mod_q) % &self.q
        }
    }

    //cond1: r1 =alpha^s *y1^c  mod p
    //cond2: r2 =beta^s *y2^c  mod p
    //returns true if both conditions are satisfied
    //r1, r2, y1, y2, alpha, beta, c, s, p are BigUint
    //p is the modulus, c is the challenge, s is the response, alpha and beta are the public keys, y1 and y2 are the commitments
    //r1 and r2 are the responses to be verified
    pub fn verify(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,

        c: &BigUint,
        s: &BigUint,
    ) -> bool {
        let cond1: bool = *r1
            == ((&self.alpha.modpow(s, &self.p)) % &self.p * (y1.modpow(c, &self.p)) % &self.p)
                % &self.p;

        let cond2: bool = *r2
            == ((&self.beta.modpow(s, &self.p)) % &self.p * (y2.modpow(c, &self.p)) % &self.p)
                % &self.p;

        cond1 && cond2
    }

    pub fn generate_random_below(bound: &BigUint) -> BigUint {
        let mut rng = rand::thread_rng();
        // Create a random number generator

        rng.gen_biguint_below(bound) // The `gen_biguint_below` function is provided by the `num-bigint` crate with the `rand` feature enabled
    } // Generates a random BigUint below the specified bound
}

#[cfg(test)]
mod test {
    use std::result;

    //    use std::collections::btree_map::Keys;
    use super::*; // Import the functions to be tested

    #[test]
    fn test_toy_example() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p: BigUint = BigUint::from(23u32);
        let q: BigUint = BigUint::from(11u32);

        let zkp = ZKP {
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);

        let c = BigUint::from(4u32);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);
        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = zkp.solve(&k, &c, &x);
        assert_eq!(s, BigUint::from(5u32));

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);

        //fake secret:

        let fake_x = BigUint::from(7u32);
        let fake_s = zkp.solve(&k, &c, &fake_x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &fake_s);
        assert!(!result);

        println!(
            "alpha: {}, beta: {}, p: {}, x: {}, k: {}, c: {}",
            alpha, beta, p, x, k, c
        );
        println!("y1: {}, y2: {}, c: {}", y1, y2, c);
        println!("r1: {}, r2: {}, s: {}", r1, r2, s);
        println!("Verification result: {}", result);
    }

    #[test]
    fn test_toy_example_with_random_numbers() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p: BigUint = BigUint::from(23u32);
        let q: BigUint = BigUint::from(11u32);

        let zkp = ZKP {
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };
        let x = BigUint::from(6u32);
        let k = ZKP::generate_random_below(&q);

        let c = ZKP::generate_random_below(&q);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);

        let s = zkp.solve(&k, &c, &x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);
    }
}
