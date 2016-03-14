#include "ad.h"

int main(int argc,char *argv[]){
    int r;
    if (argc ==1){
        printf("-e для eth0, -w для wlan0\n");
        return 0;
    }
    while((r=getopt(argc,argv,"we"))!=-1)
        {
            switch(r)
            {
            case 'w':
                printf("Работа с интерфейсом wlan0\n");
                sniff(1);
                break;
            case 'e':
                printf("Работа с интерфейсом eth0\n");
                sniff(2);
                break;
            case '?': printf("-e для eth0, -w для wlan0\n");
                return 0;
            }
        }

    return(0);


}

