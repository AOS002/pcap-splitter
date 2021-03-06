#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

int fileExists(char *fname)
{
  FILE *fptr=fopen(fname,"r");
  if(fptr)
  {
    fclose(fptr);
    return 1;
  }
  else
    return 0;
}

struct Connection  
{ 
  char source_ip[INET_ADDRSTRLEN];
  char dest_ip[INET_ADDRSTRLEN];
  u_short source_port;
  u_short dest_port;
  int file_name_no;
  struct Connection *next; 
};

struct Connection * getConnection(struct Connection *c, struct Connection *new) 
{
  //Return the newly inserted node if the connection does not already exist, else returns the node with the existing connection
  struct Connection *prev_c;
  struct Connection *start_node=c;   
  int result1,result2;

  if(c == NULL)
  {    
    new->file_name_no=0;    
    return new;
  }

  while (c != NULL) 
  {
    result1=strcmp(c->source_ip,new->source_ip)==0 && strcmp(c->dest_ip,new->dest_ip)==0 && c->source_port==new->source_port && c->dest_port==new->dest_port;
    result2=strcmp(c->source_ip,new->dest_ip)==0 && strcmp(c->dest_ip,new->source_ip)==0 && c->source_port==new->dest_port && c->dest_port==new->source_port;    
   
    if(result2 || result1)
    {     
      return c;
    }
    prev_c=c;     
    c = c->next; 
  }
  new->file_name_no=prev_c->file_name_no+1;  
  prev_c->next=new;
  return new;
}


struct Connection *head = NULL;
char *output_directory_path, *src_ip_filter, *non_tcp_file_path;  

void splitPcap(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

  const struct ether_header* eth_header;
  const struct ip* ip_header;
  const struct tcphdr* tcp_header;
  int size_eth_header;
  int size_ip_header;
  int is_tcp=0;
  pcap_dumper_t *dumper;
  pcap_t *descr=(pcap_t*)args;
  eth_header = (struct ether_header*)(packet);

  //Check if it is of type IP
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
  {
    size_eth_header = sizeof(struct ether_header);
    ip_header = (struct ip*)(packet + size_eth_header);    
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    //Check if it is of type TCP & also whether the IP src filter is set
    // The order of the OR condition is important, since if it is NULL it cannot do strcmp
    if((ip_header->ip_p == IPPROTO_TCP) && (src_ip_filter==NULL || strcmp(src_ip_filter,source_ip)==0))
    {
      is_tcp=1;
      size_ip_header = sizeof(struct ip);
      tcp_header = (struct tcphdr*)(packet + size_eth_header +size_ip_header);

      u_short source_port;
      u_short dest_port;
      source_port = ntohs(tcp_header->th_sport);
      dest_port = ntohs(tcp_header->th_dport);           

      struct Connection *new = (struct Connection*)malloc(sizeof(struct Connection));      
      strcpy(new->source_ip,source_ip);
      strcpy(new->dest_ip,dest_ip);
      new->source_port=source_port;
      new->dest_port=dest_port;
      new->next=NULL;

      struct Connection *inserted_node;
      inserted_node=getConnection(head,new);
      if (head==NULL)
      {
        head=inserted_node;
      }

      char fname[20];      
      sprintf (fname, "%s%s%d%s",output_directory_path,"/" ,inserted_node->file_name_no,".pcap");

      if (fileExists(fname) == 1)
      {
        dumper = pcap_dump_open_append(descr, fname);
      }
      else
      {
        dumper = pcap_dump_open(descr, fname); 
      }
      pcap_dump((u_char*)dumper,header,packet);
      pcap_dump_close(dumper);
    }
    
  }
  if ((non_tcp_file_path!=NULL) && (is_tcp==0))
    {
      if (fileExists(non_tcp_file_path) == 1)
      {
        dumper = pcap_dump_open_append(descr, non_tcp_file_path);
      }
      else
      {
        dumper = pcap_dump_open(descr, non_tcp_file_path); 
      }
      pcap_dump((u_char*)dumper,header,packet);
      pcap_dump_close(dumper);
    }  
}

int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *descr;
  char *file_path;
  int c;

  while ((c = getopt (argc, argv, "i:o:f:j:")) != -1)
  {
    switch(c)
    {
      //-i file_path: (Mandatory) Specifies a pcap file as input.
      case 'i':
        file_path=optarg;
        break;

      //-o directory_path: (Mandatory) Specifies a directory to output pcap files to.
      case 'o':
        output_directory_path=optarg;
        break;

      //-f src_ip: (Optional) If this option is given, ignore all traffic that is not from the specified source IP.
      case 'f':
        src_ip_filter=optarg;
        break;

      //-j file_path: (Optional) If this option is given, all non-TCP traffic should be stored into a single pcap file. Otherwise, all non-TCP traffic should be ignored.
      case 'j':
        non_tcp_file_path=optarg;
        break;
    }    
  }

  descr = pcap_open_offline(file_path, errbuf);  
  //descr = pcap_open_offline("temp.pcap", errbuf);  
  if(descr == NULL)
  {
    printf("Unable to open file!");
  }   
  pcap_loop(descr,0,splitPcap,(u_char*)descr);
  return 0;
}