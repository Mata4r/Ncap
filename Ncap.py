from scapy.all import IP, ICMP, sniff,sr1, Ether, ARP, srp, TCP,  get_if_list, socket
from termcolor import colored

bracket1 = (colored('[','red'))
bracket2 = (colored(']','red'))

print()
print("""\t
\t███╗   ██╗ ██████╗ █████╗ ██████╗ 
\t████╗  ██║██╔════╝██╔══██╗██╔══██╗
\t██╔██╗ ██║██║     ███████║██████╔╝
\t██║╚██╗██║██║     ██╔══██║██╔═══╝ 
\t██║ ╚████║╚██████╗██║  ██║██║     
\t╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝""")
print()
print(colored('\t██████████████████████████████████████████████████████', 'red'))
print()
print(f'\t[1] Sniff')
print(f'\t[2] Ping')
print(f'\t[3] Arp Spoof')
print(colored(f'\t━━━', 'red'))
print(f'\t[4] Web discovery')
print(f'\t[5] Web Ping')
print()

def Sniffing():
    try:
        Interface = input('\t[iface] ') 
        Filter = input('\t[filter] ')
        print()

        Filter_lowering = Filter.lower() 

        print(colored('\tCapture initiated...','red'))

        sniff_pair = sniff(iface=Interface,filter=Filter_lowering ,prn=lambda x: x.summary())
    except:
        print(colored('\tCapture terminated','red'))
        print(colored(f'\tAn error occurred: No such interface exists: {Interface}','yellow'))

def Pinging():
    try:
        Target_ip = input('\t[ip] ') 
        print(colored('\tPing begin...','red'))

        ICMP_packet = IP(dst=Target_ip)/ICMP() 
        ICMP_replay = sr1(ICMP_packet,
                       timeout=5,
                         verbose=0 )
        if ICMP_replay:
                      print()
                      print('\t ip\t\t Status')
                      print(colored('\t ━━━\t\t ━━━━━━', 'red'))
                      print(f'\t {Target_ip}\t UP')
        else:
            print()
            print('\t ip\t\t Status')
            print(colored('\t ━━━\t\t ━━━━━━━━━━━━━━━━━━━━━', 'red'))
            print(f'\t {Target_ip}\t Down / not responding')
    except:
        print(colored('\tPing terminated','red'))
        print(colored(f'\tAn error occurred: No such device exists: {Target_ip}','yellow'))
 
def ArpSpoof():
    try:
        Target_ip = input('\t[subnet] ') 
        print(colored('\tSpoof begin...','red'))
    
        ARP_packet = Ether(dst='ff:ff:ff:ff:ff:ff')\
        /ARP(pdst=Target_ip) 
        SntRcv = srp(ARP_packet, timeout=5, verbose=0)
        print()
        print('\tIPv4 Address\t\tBSSID')
        for sent, received in SntRcv[0]: 
            print(f"\t{received.psrc}\t\t{received.hwsrc}") 
    except:
        print(colored('\tArpSpoof terminated','red'))
        print(colored(f'\tAn error occurred: No such device exists: {Target_ip}','yellow'))

def Web_Discovery():
    try:
       Target_Domain = input('\t[Domain] ')
       print(colored('\tFetching IP...', 'red'))
       Spoof_ip = socket.gethostbyname(Target_Domain).lower()
       if Spoof_ip:
          print()
          print('\t Domain\t\t IP')
          print(colored('\t ━━━━━━\t\t ━━━', 'red'))
          print('\t',Target_Domain,'\t',Spoof_ip)
    except:
        print()
        print(colored('\tWeb_Discovery terminated','red'))
        print(colored(f'\tAn error occurred: No such domain exists: {Target_Domain}','yellow'))
    
def Web_Ping():
    try:
       Target_Domain = input('\t[Domain] ')
       print(colored('\tPing Begin...','red'))
       Web_ping_pack = IP\
        (dst=Target_Domain)\
        /ICMP()
    
       if Web_ping_pack:
          print()
          print('\t Domain\t\t Status')
          print(colored('\t ━━━━━━\t\t ━━━━━━', 'red'))
          print(f'\t {Target_Domain}\t UP')
       else:
          print()
          print('\t Domain\t\t Status')
          print(f'{Target_Domain}\t DOWN or Unresponsive')
    except:
      print(colored('\tWeb_Ping terminated','red'))
      print(colored(f'\tAn error occurred: No such domain exists: {Target_Domain}','yellow'))
       
while True:

 option = input('\t[+] ')

 if option=='1':
     Sniffing()

 elif option=='2':
     Pinging()

 elif option=='3':
     ArpSpoof()

 elif option=='4':
     Web_Discovery()
     
 elif option=='5':
     Web_Ping()
 else:
     print(colored(f'\tInvalid option. Please choose a valid number','yellow'))