import hashlib
import math
from random import randint
from SM2_ECG import *
import config
from Prepare import *
def key_generation_1():
	n = config.get_n()
	Gx = config.get_Gx()
	Gy = config.get_Gy()
	# A1. 用随机数发生器产生随机数rA ∈[1, n-1]
	rA = PRG_function(1, n-1)
	# A2. 计算椭圆曲线点RA = [rA]G=(x1,y1)
	RA = ECG_k_point(rA, Point(Gx, Gy))
	# A3. 将RA发送给用户B
	return RA, rA

def get_ZA_ZB(IDA, IDB, PA, PB):
	ZA = get_Z(IDA, PA)
	ZA = remove_0b_at_beginning(ZA)
	ZB = get_Z(IDB, PB)
	ZB = remove_0b_at_beginning(ZB)
	return ZA, ZB

def key_generation_2(ZA, ZB, r_self, R_self, R_opposite, d_self, P_self, P_opposite, klen, is_send):
	q = config.get_q()
	a = config.get_a()
	b = config.get_b()
	n = config.get_n()
	Gx = config.get_Gx()
	Gy = config.get_Gy()
	h = config.get_h()
	w = math.ceil( math.ceil( math.log(n, 2) )/2 ) - 1
	# A4. 从R_self中取出域元素x_self，将x_self的数据类型转换为整数，计算x_self_ = 2w +(x_self&(2w−1))； 
	x_self = R_self.x
	x_self = ele_to_int(x_self)
	y_self = R_self.y
	y_self = ele_to_int(y_self)
	x_self_ = 2**w + (x_self & (2**w - 1))
	# A5. 计算t_self = (d_self + ¯ x_self·r_self)modn
	t_self = (d_self+x_self_*r_self) % n
	# A6.1 验证R_opposite是否满足椭圆曲线方程，若不满足则协商失败；
	# A6.2 否则从R_opposite中取出域元素x_opposite，将x_opposite的数据类型转换为整数，计算x_opposite_ = 2w +(x_opposite&(2w−1))； 
	x_opposite = R_opposite.x
	x_opposite = ele_to_int(x_opposite)
	y_opposite = R_opposite.y
	y_opposite = ele_to_int(y_opposite)
	if (y_opposite**2)%q != (x_opposite**3 + a*x_opposite + b)%q:
		print("keyExchange Fail: R_opposite do not satisfy the equation")
		return -1
	x_opposite_ = 2**w + (x_opposite & (2**w - 1))
	# A7.1 计算椭圆曲线点U_self = [h·t_self](P_opposite +[x_opposite_]R_opposite) = (xU_self,yU_self)
	# A7.2 若U_self是无穷远点，则A协商失败；否则将xU_self、yU_self的数据类型转换为比特串
	U_self = ECG_k_point(h*t_self, ECG_ele_add(P_opposite, ECG_k_point(x_opposite_, R_opposite)))
	xU_self = U_self.x
	yU_self = U_self.y
	xU_self = bytes_to_bits(ele_to_bytes(xU_self))
	xU_self = remove_0b_at_beginning(xU_self)
	yU_self = bytes_to_bits(ele_to_bytes(yU_self))
	yU_self = remove_0b_at_beginning(yU_self)
	# A8. 计算KA=KDF(xU_self ∥yU_self ∥ZA ∥ZB,klen)
	k_self = KDF(xU_self+yU_self+ZA+ZB, klen)
	# A9. 将R_self的坐标x_self、y_self 和R_opposite的坐标x_opposite、y_opposite的数据类型转换为比特串
	# 计算S_test= Hash(0x02∥yU_self ∥Hash(xU_self ∥ZA ∥ZB ∥x_self ∥y_self ∥x_opposite ∥y_opposite))
	# 并检验S_test=SB是否成立，若等式不成立则从B到A的密钥确认失败；

	x_self = bytes_to_bits(ele_to_bytes(x_self))
	x_self = remove_0b_at_beginning(x_self)
	y_self = bytes_to_bits(ele_to_bytes(y_self))
	y_self = remove_0b_at_beginning(y_self)
	x_opposite = bytes_to_bits(ele_to_bytes(x_opposite))
	x_opposite = remove_0b_at_beginning(x_opposite)
	y_opposite = bytes_to_bits(ele_to_bytes(y_opposite))
	y_opposite = remove_0b_at_beginning(y_opposite)
	if is_send:
		prefix = remove_0b_at_beginning(bytes_to_bits(int_to_bytes(2, 1)))
		S_test = hash_function(prefix+yU_self+hash_function(xU_self+ZA+ZB+x_opposite+y_opposite+x_self+y_self))
	else:
		prefix = remove_0b_at_beginning(bytes_to_bits(int_to_bytes(3, 1)))
		S_test = hash_function(prefix+yU_self+hash_function(xU_self+ZA+ZB+x_self+y_self+x_opposite+y_opposite))
	S_test = remove_0b_at_beginning(S_test)
	# A10. (选项)计算S_target= Hash(0x03∥yU_self ∥Hash(xU_self ∥ZA ∥ZB ∥x_self ∥y_self ∥x_opposite ∥y_opposite))，并将S_target发送给用户B
	if is_send:
		prefix = remove_0b_at_beginning(bytes_to_bits(int_to_bytes(3, 1)))
		S_target = hash_function(prefix+yU_self+hash_function(xU_self+ZA+ZB+x_opposite+y_opposite+x_self+y_self))
	else:
		prefix = remove_0b_at_beginning(bytes_to_bits(int_to_bytes(2, 1)))
		S_target = hash_function(prefix+yU_self+hash_function(xU_self+ZA+ZB+x_self+y_self+x_opposite+y_opposite))
	S_target = remove_0b_at_beginning(S_target)
	return k_self, S_target, S_test ,x_self_ ,t_self ,x_opposite_,U_self

def key_generation_3(S_target, S_test):
	if S_test != S_target:
		# print('keyExchange Fail: S1 unequal SB')
		return False
	return True

### test keyExchange ###
# config.default_config()
# parameters = config.get_parameters()
# key = key_pair_generation(parameters)
# dA = key[0]
# PA = key[1]
# key = key_pair_generation(parameters)
# dB = key[0]
# PB = key[1]
# klen = 128

# IDA = 'ALICE123@YAHOO.COM'
# IDB = 'BILL456@YAHOO.COM'
# RA, rA = key_generation_1()
# RB, rB = key_generation_1()
# ZA, ZB = get_ZA_ZB(IDA, IDB, PA, PB)
# kB, SB, S2 = key_generation_2(ZA, ZB, rB, RB, RA, dB, PB, PA, klen, 0)
# print('kB', kB)
# print('---------------------------------------------------------')
# kA, SA, S1 = key_generation_2(ZA, ZB, rA, RA, RB, dA, PA, PB, klen, 1)
# print('kA', kA)
# key_generation_3(SB, S1)
# key_generation_3(SA, S2)
