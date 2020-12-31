import binascii
from django.http import JsonResponse
from django.http import HttpResponse
from cryptoFunction import sm2_moudle,sm2_lowmod,SM2_keyExchange,bruteforce,pollardsrho,babygiantstep
# Create your views here
import urllib.request
from django.shortcuts import render_to_response, render, redirect

from pycipher import Autokey
from pycipher import Vigenere
import json
import time

sm2_p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
sm2_a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
sm2_b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
sm2_n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
sm2_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
sm2_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
sm2_G = [sm2_Gx, sm2_Gy]
sm2_r = 0
sm2_s = 0
sm2_Z_A = ''
ex_key1 = []
ex_key2 = []
len_PAx = 0
len_PAy = 0
len_PBx = 0
len_PBy = 0


#ecc
def ecc(request):
    if request.method=='POST':
        key=request.POST['key']
        input = request.POST['input']
        type1=request.POST['type']
        Pa = request.POST['Pa']
        if type1=="ve":
            C,k,C1,x2,y2,ml,t,C2,C3 = sm2_moudle.Encrypt(input,Pa,64,0)
            # print(type(k),type(C1),type(x2),type(y2),type(ml),type(t),type(C2),type(C3),sep = "\n")
            response = {"type" : "ve" , "miwen" : C , "k" : k,"C1" : C1 ,"C2" : C2,"C3" : C3 ,"x2" : x2,"y2" : y2 ,"ml" : hex(ml),"t" : t}
        elif type1=="vd":
            m,x2,y2,t,M_M,u = sm2_moudle.Decrypt(input,key,64)
            # print(type(x2),type(y2),type(t),type(M_M),type(u),sep = "\n")
            M = bytes.fromhex(m)
            response = {"type" : "vd" , "mingwen" : M.decode() , "x2" : x2,"y2" : y2 , "t" : t , "M_M": M_M, "u" : u}
        elif type1 == "sc":
            d,Pa = sm2_moudle.generate_keys(64)
            response = {"type" : "sc","gongyao" : Pa , "siyao" : d}
        else:
            response={"type" : "err" } 
        # response = {"miwen" : output}
        return HttpResponse(json.dumps(response),content_type = "application/json")
    else:
        return render(request, 'ecc.html')
#ecc
def exchange(request):
    if request.method=='POST':
        global ex_key1,ex_key2,len_PAx,len_PAy,len_PBx,len_PBy
        dA_=request.POST['key']
        dA = int(dA_,16)
        dB_=request.POST['key2']
        dB = int(dB_,16)
        # input = request.POST['input']
        ida = request.POST['ida']
        idb = request.POST['idb']
        type1=request.POST['type']
        PA_ = request.POST['Pa']
        PB_ = request.POST['Pa2']
        if type1=="exchange":
            # global ex_key1,ex_key2
            dA = ex_key1[0]
            PA = ex_key1[1]

            ex_key1[1].x = int(PA_[0:len_PAx ],16)
            ex_key1[1].y = int(PA_[len_PAx : ],16)

            dB = ex_key2[0]
            PB = ex_key2[1]

            ex_key2[1].x = int(PB_[0:len_PBx ],16)
            ex_key2[1].y = int(PB_[len_PBx : ],16)
            SM2_keyExchange.config.default_config()
            RA, rA = SM2_keyExchange.key_generation_1()

            RB, rB = SM2_keyExchange.key_generation_1()
            ZA, ZB = SM2_keyExchange.get_ZA_ZB(ida, idb, PA, PB)
            # for i in SM2_keyExchange.key_generation_2(ZA, ZB, rB, RB, RA, dB, PB, PA, 128, 0):
            #     print(type(i))
            kB, SB, S2,x_self_1 ,t_self1 ,x_opposite_1,U_self1 = SM2_keyExchange.key_generation_2(ZA, ZB, rB, RB, RA, dB, PB, PA, 128, 0)
            kA, SA, S1,x_self_2 ,t_self2 ,x_opposite_2,U_self2 = SM2_keyExchange.key_generation_2(ZA, ZB, rA, RA, RB, dA, PA, PB, 128, 1)
            b2a = SM2_keyExchange.key_generation_3(SB, S1)
            if(b2a):
                b2a_ = 'A协商成功'
            else:
                b2a_ = 'A协商失败'
            
            a2b = SM2_keyExchange.key_generation_3(SA, S2)
            if(a2b):
                a2b_ = 'B协商成功'
            else:
                a2b_ = "B协商失败"
            response = {"type" : "exchange" , "b2a" : b2a_ , "a2b" : a2b_, "RA" : hex(RA.x).replace('0x','') + hex(RA.y).replace('0x','') , \
                "rA" : hex(rA).replace('0x','') , "RB" : hex(RB.x).replace('0x','') + hex(RB.y).replace('0x','') , "rB" : hex(rB).replace('0x','') , "kB" : hex(int(kB,2)).replace('0x',''), "SB":hex(int(SB,2)).replace('0x','') \
                    ,"S2" :hex(int(S2,2)).replace('0x',''),"x_self_1" :hex(x_self_1).replace('0x','') , "t_self1" : hex(t_self1).replace('0x','') ,"x_opposite_1":hex(x_opposite_1).replace('0x','') , \
                        "U_self1" :hex(U_self1.x).replace('0x','') + hex(U_self1.y).replace('0x','') , "kA" : hex(int(kA,2)).replace('0x','') , "SA" : hex(int(SA,2)).replace('0x','') ,"S1" : hex(int(S1,2)).replace('0x','') ,\
                         "x_self_2" : hex(x_self_2).replace('0x','') ,"t_self2" :hex(t_self2).replace('0x',''),"x_opposite_2" : hex(x_opposite_2).replace('0x',''),"U_self2" :hex(U_self2.x).replace('0x','') + hex(U_self2.y).replace('0x','') } 
        elif type1=="vd":
            m,x2,y2,t,M_M,u = sm2_moudle.Decrypt(input,key,64)
            # print(type(x2),type(y2),type(t),type(M_M),type(u),sep = "\n")
            M = bytes.fromhex(m)
            response = {"type" : "vd" , "mingwen" : M.decode() , "x2" : x2,"y2" : y2 , "t" : t , "M_M": M_M, "u" : u}
        elif type1 == "sc":
            
            SM2_keyExchange.config.default_config()
            parameters = SM2_keyExchange.config.get_parameters()
            ex_key1 = SM2_keyExchange.key_pair_generation(parameters)
            dA = ex_key1[0]
            PA = ex_key1[1]

            len_PAx = len(hex(PA.x).replace('0x',''))
            len_PAy = len(hex(PA.y).replace('0x',''))


            Pa = hex(PA.x).replace('0x','') + hex(PA.y).replace('0x','')
            ex_key2 = SM2_keyExchange.key_pair_generation(parameters)
            dB = ex_key2[0]
            PB = ex_key2[1]
            len_PBx = len(hex(PB.x).replace('0x',''))
            len_PBy = len(hex(PB.y).replace('0x',''))
            Pa2 = hex(PB.x).replace('0x','') + hex(PB.y).replace('0x','')
            response = {"type" : "sc","gongyao" : Pa , "siyao" : hex(dA).replace('0x','') , "gongyao2" : Pa2 ,"siyao2" : hex(dB).replace('0x','')}
        else:
            response={"type" : "err" } 
        # response = {"miwen" : output}
        return HttpResponse(json.dumps(response),content_type = "application/json")
    else:
        return render(request, 'sm2exchange.html')

def sign(request):
    if request.method=='POST':
        key=request.POST['key']
        input = request.POST['input']
        type1=request.POST['type']
        Pa = request.POST['Pa']
        signid = request.POST['signid']
        sm2_Pa = []

        if type1=="sign":
            sm2_Pa.append(int(Pa[0:len(Pa)//2 ],16))
            sm2_Pa.append(int(Pa[len(Pa)//2 : ],16))
            sm2_key = int(key,16)
            global sm2_r,sm2_s,sm2_Z_A
            sm2_r, sm2_s, sm2_Z_A,M_M,e,k,x_1,y_1 = sm2_lowmod.SM2_CA_Signature(sm2_a,sm2_b,sm2_p,sm2_n,sm2_G,sm2_key,sm2_Pa,signid,input)
            # print(type(M_M),type(e),type(k),type(x_1),type(y_1),sep = '\n')
            response = {"type" : "sign" , "r" : hex(sm2_r).replace('0x','') ,"s" : hex(sm2_s).replace('0x','') ,"M_M" : hex(int(M_M,2)) ,"e" : hex(int(e,2)) , "k" : hex(k) ,"x_1" : hex(x_1) , "y_1" : hex(y_1) }
        elif type1=="check":
            sm2_Pa.append(int(Pa[0:len(Pa)//2 ],16))
            sm2_Pa.append(int(Pa[len(Pa)//2 : ],16))

            ans,M_M,e,t,x_1,y_1,R = sm2_lowmod.SM2_CA_Check(sm2_a,sm2_b,sm2_p,sm2_n,sm2_G,sm2_Z_A,sm2_Pa,input,sm2_r,sm2_s)
            # print(type(M_M),type(e),type(t),type(x_1),type(y_1),type(R),sep = "\n")
            if(ans == True):
                result = "CHECK SUCCESS."
            else:
                result = "CHECK FAILED."
            response = {"type" : "check" , "result" : result , "M_M" : hex(int(M_M,2)) , "e" : hex(int(e,2)), "t" : hex(t), "x_1" : hex(x_1) , "y_1" : hex(y_1) , "R" : hex(R)}
        elif type1 == "sc":
            d,Pa = sm2_moudle.generate_keys(64)
            response = {"type" : "sc","gongyao" : Pa , "siyao" : d}
        else:
            response={"type" : "err" } 
        # response = {"miwen" : output}
        return HttpResponse(json.dumps(response),content_type = "application/json")
    else:
        return render(request, 'sm2sign.html')

def security(request):
    if request.method=='POST':

        type1=request.POST['type']

        if type1=="pollardsrho":
            ans = pollardsrho.main()
            # print(ans)
            response = {"type" : "pollardsrho" , "ans" : ans}
        elif type1=="babygiantstep":

            ans = babygiantstep.main()
            response = {"type" : "babygiantstep" , "ans" : ans }
        elif type1 == "bruteforce":
            ans = bruteforce.main()
            response = {"type" : "bruteforce","ans" : ans }
        else:
            response={"type" : "err" } 
        # response = {"miwen" : output}
        return HttpResponse(json.dumps(response),content_type = "application/json")
    else:
        return render(request, 'security.html')


def compare(request):
    if request.method=='POST':
        key=request.POST['key']
        input = request.POST['input']
        type1=request.POST['type']
        Pa = request.POST['Pa']
        if type1=="bef":
            # print("Pa = " + Pa)
            sm2_Pa = []
            sm2_Pa.append(int(Pa[0:len(Pa)//2 ],16))
            sm2_Pa.append(int(Pa[len(Pa)//2 : ],16))
            sm2_key = int(key,16)
            # print(sm2_Pa)
            c1 = time.time()
            C = sm2_lowmod.SM2_Encrypt(sm2_a,sm2_b,sm2_p,sm2_n,sm2_G,sm2_Pa,input)
            CM = sm2_lowmod.SM3_Decode(C)
            c2 = time.time()
            en_time = c2 - c1
            m1 = time.time()
            M = sm2_lowmod.SM2_Decrypt(sm2_a,sm2_b,sm2_p,sm2_n,sm2_G,sm2_key,C)
            m2 = time.time()
            de_time = m2-m1
            response = {"type" : "bef" , "miwen" : CM , "mingwen" : M , "entime" : str(en_time) , "detime" : str(de_time)}
        elif type1=="aft":
            c1 = time.time()
            C,k,C1,x2,y2,ml,t,C2,C3 = sm2_moudle.Encrypt(input,Pa,64,0)
            c2 = time.time()
            en_time = c2 - c1
            m1 = time.time()
            # print(C)
            # print(key)
            # print(Pa)
            m,x2,y2,t,M_M,u  = sm2_moudle.Decrypt(C,key,64)
            M = bytes.fromhex(m)
            m2 = time.time()
            de_time = m2-m1
            response = {"type" : "aft" , "mingwen" : M.decode() ,"miwen" : C , "entime" : str(en_time) , "detime" : str(de_time)}
        elif type1 == "sc":
            d,Pa = sm2_moudle.generate_keys(64)
            response = {"type" : "sc","gongyao" : Pa , "siyao" : d}
        else:
            response={"type" : "err" } 
        # response = {"miwen" : output}
        return HttpResponse(json.dumps(response),content_type = "application/json")
    else:
        return render(request, 'sm2compare.html')

