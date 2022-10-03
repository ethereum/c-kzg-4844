import atexit
import ckzg
import kzg_proofs
import random
from py_ecc import optimized_bls12_381 as b
from py_ecc.bls.point_compression import compress_G1, decompress_G1, decompress_G2


polynomial = [random.randint(0, kzg_proofs.MODULUS) for i in range(4096)]
n = len(polynomial)

x = 9283547894352

y = kzg_proofs.eval_poly_at(polynomial, x)

root_of_unity = kzg_proofs.get_root_of_unity(n)
roots_of_unity = [pow(root_of_unity, i, kzg_proofs.MODULUS) for i in range(n)]

polynomial_l = [kzg_proofs.eval_poly_at(polynomial, w) for w in roots_of_unity]

def evaluate_polynomial_in_evaluation_form(polynomial, z, roots_of_unity):

    width = len(polynomial)
    inverse_width =kzg_proofs.inv(width)

    # Make sure we won't divide by zero during division
    assert z not in roots_of_unity

    result = 0
    for i in range(width):
        result += kzg_proofs.div(polynomial[i] * roots_of_unity[i], (z - roots_of_unity[i]))
    result = result * (pow(z, width, kzg_proofs.MODULUS) - 1) * inverse_width % kzg_proofs.MODULUS
    return result

y2 = evaluate_polynomial_in_evaluation_form(polynomial_l, x, roots_of_unity)

assert y == y2

polynomial_l_rbo = kzg_proofs.list_to_reverse_bit_order(polynomial_l)
roots_of_unity_rbo = kzg_proofs.list_to_reverse_bit_order(roots_of_unity)

y3 = evaluate_polynomial_in_evaluation_form(polynomial_l_rbo, x, roots_of_unity_rbo)

assert y == y3

ts = ckzg.load_trusted_setup("../../src/trusted_setup.txt")
ckzg_poly = ckzg.alloc_polynomial([ckzg.bytes_to_bls_field(r.to_bytes(32, "little")) for r in polynomial_l_rbo])
ckzg_y4 = ckzg.evaluate_polynomial_in_evaluation_form(ckzg_poly, ckzg.bytes_to_bls_field(x.to_bytes(32, "little")), ts)
y4 = ckzg.int_from_bls_field(ckzg_y4)

assert y == y4

def load_trusted_setup(filename):
    with open(filename, "r") as f:
        g1_length = int(f.readline())
        g2_length = int(f.readline())
        g1_setup = []
        g2_setup = []
        for i in range(g1_length):
            g1_setup.append(decompress_G1(int(f.readline(), 16)))
        #for i in range(g2_length):
        #    l = f.readline()
        #    g2_setup.append(decompress_G2((int(l[:48], 16), int(l[48:], 16))))
    return [g1_setup, g2_setup]

ts_pyecc = load_trusted_setup("../../src/trusted_setup.txt")

commitment_pyecc = kzg_proofs.commit_to_poly(polynomial, ts_pyecc)
commitment_ckzg  = ckzg.blob_to_kzg_commitment([ckzg.bytes_to_bls_field(r.to_bytes(32, "little")) for r in polynomial_l_rbo], ts)

assert compress_G1(commitment_pyecc).to_bytes(48, "big") == ckzg.bytes_from_g1(commitment_ckzg)

proof_pyecc = kzg_proofs.compute_proof_single(polynomial, x, ts_pyecc)
proof_ckzg = ckzg.compute_kzg_proof(ckzg_poly, ckzg.bytes_to_bls_field(x.to_bytes(32, "little")), ts)

assert compress_G1(proof_pyecc).to_bytes(48, "big") == ckzg.bytes_from_g1(proof_ckzg)
