import math
import random

from common import tinycurve as curve


def log(p, q):
    assert curve.is_on_curve(p)
    assert curve.is_on_curve(q)

    sqrt_n = int(math.sqrt(curve.n)) + 1

    # Compute the baby steps and store them in the 'precomputed' hash table.
    r = None
    precomputed = {None: 0}

    for a in range(1, sqrt_n):
        r = curve.add(r, p)
        precomputed[r] = a

    # Now compute the giant steps and check the hash table for any
    # matching point.
    r = q
    s = curve.mult(sqrt_n, curve.neg(p))

    for b in range(sqrt_n):
        try:
            a = precomputed[r]
        except KeyError:
            pass
        else:
            steps = sqrt_n + b
            logarithm = a + sqrt_n * b
            return logarithm, steps

        r = curve.add(r, s)

    raise AssertionError('logarithm not found')


def main():
    x = random.randrange(1, curve.n)
    p = curve.g
    q = curve.mult(x, p)

    ans ='椭圆曲线: {}'.format(curve) + '\n'
    ans +='曲线的阶: {}'.format(curve.n)+ '\n'
    ans +='p = (0x{:x}, 0x{:x})'.format(*p)+ '\n'
    ans +='q = (0x{:x}, 0x{:x})'.format(*q)+ '\n'
    ans +=str(x) + '* p = q'+ '\n'
    y, steps = log(p, q)
    ans += 'log(p, q) ='+ str(y)+ '\n'
    ans+= '一共尝试了 '+ str(steps) + ' 次'+ '\n'

    return ans
    assert x == y


# if __name__ == '__main__':
#     main()