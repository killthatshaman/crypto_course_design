import random

from common import tinycurve as curve


def log(p, q):
    assert curve.is_on_curve(p)
    assert curve.is_on_curve(q)

    start = random.randrange(curve.n)
    r = curve.mult(start, p)

    for x in range(curve.n):
        if q == r:
            logarithm = (start + x) % curve.n
            steps = x + 1
            return logarithm, steps
        r = curve.add(r, p)

    raise AssertionError('logarithm not found')


def main():
    x = random.randrange(curve.n)
    p = curve.g
    q = curve.mult(x, p)

    ans ='椭圆曲线: {}'.format(curve) + '\n'
    ans +='曲线的阶: {}'.format(curve.n)+ '\n'
    ans +='p = (0x{:x}, 0x{:x})'.format(*p)+ '\n'
    ans +='q = (0x{:x}, 0x{:x})'.format(*q)+ '\n'
    ans += str(x) + '* p = q'+ '\n'

    y, steps = log(p, q)
    ans +='log(p, q) =' + str(y) + '\n'
    ans+= '一共尝试了 '+ str(steps) + ' 次'+ '\n'
    return ans
    assert x == y


# if __name__ == '__main__':
#     main()