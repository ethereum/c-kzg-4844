import ckzg
c1 = ckzg.fr_from_uint64s((12,13,0,0))
c2 = ckzg.fr_from_uint64(2)
c3 = ckzg.fr_from_uint64s((1,0,0,0))
c4 = ckzg.fr_sub(c2, c3)
assert ckzg.fr_is_one(c4)
assert ckzg.fr_equal(c3, c4)
coeffs = [c1, c2, c3, c4]
cfa = ckzg.frArray(len(coeffs))
for i, c in enumerate(coeffs):
    cfa[i] = c
ret, pptr = ckzg.new_poly_with_coeffs(cfa.cast(), len(coeffs))
p = ckzg.polyp_frompointer(pptr).value()
assert p.length == 4
pcoeffs = ckzg.frArray_frompointer(p.coeffs)
assert ckzg.fr_to_uint64s(pcoeffs[1]) == (2, 0, 0, 0)
