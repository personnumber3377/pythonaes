
def coef_to_pol(where_coef_is_one: list) -> int: # Converts the coefficients to a polynomial. The list actually doesn't represent the coefficients, but the indexes where the coefficient is one. For example passing [2] to this would represent x**2 or 0b100 , not 2 . This is because this is in GF(2).
    out = 0
    for ind in where_coef_is_one:
        out |= 1 << ind
    return out

