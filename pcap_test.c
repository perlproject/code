#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <string.h>

void printout(const u_char *packet,int length);

int main()
{
  char track[] = "컨설팅"; // "특기병", "컨설팅", "포렌식"
  char name[] = "이수림";
  
  //pcap_lookupdev	
  char *device; 

  //pcap_lookupnet 
  bpf_u_int32 mask; 
  bpf_u_int32 net; //netmask 주소 저장

  //pcap_open_live
  pcap_t *pcd; //packet capture descriptor for pcap_open_live
  char errbuf[100];
  
  //pcap_compile
  struct bpf_program fp; //필터링 룰에 따라 결정될 구조체
  char *filter="tcp port 80"; //필터링 룰
  
  //pcat_next
  const u_char *packet;
  struct pcap_pkthdr h;
  int i;

  printf("[bob5][%s]pcap_test[%s]", track, name);
  printf("\n");

  //패킷을 캡쳐할 적당한 디바이스(랜카드) 찾기
  device=pcap_lookupdev(errbuf); 
  if(device==NULL) { printf("can not find dev...%s\n",errbuf);}
  printf("\ndivice: %s\n",device); //ens33

  //netmask 정보 가져오기
  if(pcap_lookupnet(device,&net,&mask,errbuf)==-1)
  {
    printf("Err in pcap_lookupnet...%s\n",errbuf);
  }
  
  //packet capture descriptor를 얻기 위해 디바이스를 엶
  pcd=pcap_open_live(device,700,1,0,errbuf); //700은 캡쳐할 바이트 수
  if(pcd==NULL) { printf("err in pcap_open_live...%s\n",errbuf);}

  //패킷 필터링 적용
  if(pcap_compile(pcd,&fp,filter,0,net)<0)
  {printf("err\n");}
  
  //pcd에 필터링을 지정
  if(pcap_setfilter(pcd,&fp)<0)
  {printf("err\n");}
  
  printf("filtering rule: %s\n",filter);
  printf("패킷을 기다리고 있습니다....\n\n");
  
  //패킷 캡쳐한 후 구조체에 정보 저장,출력(printout)
  packet=pcap_next(pcd,&h);
  printout(packet,h.len);
    
  return 0;
 }

void printout(const u_char *packet,int length)
{
  int i=0;
  int point; 
  char buf[2];
  unsigned short dport;
  u_char h[100]={0,};

  for(i=0;i<length;i++)
  { 
    h[i]=*packet; //패킷 데이터를 배열에 저장
    printf("%02x ",*packet);
    packet++; //데이터 위치 이동
  }
  
  printf("\n\n--------------------------\n");
  point=0;
  i=0;

  printf("dst.mac: %x",h[point]); 
  for(i=point+1;i<point+6;i++)
  {
    printf(":%x",h[i]);
  }
  
  point+=6;
  printf("\nsrc.mac: %x",h[point]);
  for(i=point+1;i<point+6;i++)
  {
    printf(":%x",h[i]); 
  }
  
  point+=20;
  printf("\nsrc.ip: %d",h[point]);
  for(i=point+1;i<point+4;i++)
  {
    printf(".%d",h[i]); 
  }
  
  point+=4;
  printf("\ndst.ip: %d",h[point]);
  for(i=point+1;i<point+4;i++)
  {
    printf(".%d",h[i]); 
  }
  
  point+=4;
  sprintf(buf,"%x%x",h[point],h[point+1]);
  printf("\nsrc.port: %d",*((unsigned short*)&(buf)));

  point+=2;
  printf("\ndst.port: %d",h[point+1]);
  printf("\n--------------------------\n\n");
}
