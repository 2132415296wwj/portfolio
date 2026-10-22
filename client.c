#include <sys/types.h>         
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<dirent.h>
//本机外设清单的文件名(list 选项生成,put 选项上传)
#define DEVICE_LIST_FILE "device_list.txt"
int islogin=0;
//服务端返回的可下载列表(选项4 下载时先拉取),由接收线程填充,主线程读取
char g_file_list[300][50];//显示文本
char g_file_key[300][50]; //下载标识:我上传的=文件名, 版本库=驱动名
int g_file_type[300];     //-3=我上传的文件, -5=版本库驱动包
int g_file_count=0;
volatile int g_list_ready=0;//1=列表已接收完毕
volatile int g_download_done=0;//1=本次下载已结束(完成或出错)
char loginUsername[50];
//驱动版本检测的统计信息,由发送线程设置、接收线程累加
int g_check_total=0;//本次上报的驱动总数
int g_check_recv=0;//已收到的检测结论数
int g_check_update=0;//可更新的数量
int g_check_newest=0;//已是最新的数量
int g_check_unknown=0;//版本库未收录的数量
struct net_info
{
	    int type;//1.register 2.login 3.list 4.get 5.put 6.history 7.exit 8.delete
		char username[50];//用户名
	    char password[50];//密码				   
		char filename[50];//文件名
		char info[500];//文件内容
	 	int info_len;//内容长度
};
//循环发送固定长度的数据,直到发满 len 字节(TCP 可能一次只发出一部分)
//返回值:成功返回 len,失败返回 -1
int sendn(int fd,const void* buf,int len)
{
	const char* p=(const char*)buf;
	int left=len;
	while(left>0)
	{
		int n=send(fd,p,left,0);
		if(n<=0)//n==0 表示没能发出任何数据,同样按出错处理,避免死循环
		{
			if(errno==EINTR)//被信号打断,重试
			{
				continue;
			}
			return -1;
		}
		p+=n;
		left-=n;
	}
	return len;
}
//循环接收固定长度的数据,直到收满 len 字节才返回
//粘包时多余的数据仍留在内核缓冲区,由下一次 recvn 继续读取,因此不会错位
//返回值:成功返回 len,对端关闭返回 0,失败返回 -1
int recvn(int fd,void* buf,int len)
{
	char* p=(char*)buf;
	int left=len;
	while(left>0)
	{
		int n=recv(fd,p,left,0);
		if(n==0)//对端关闭
		{
			return 0;
		}
		if(n<0)
		{
			if(errno==EINTR)
			{
				continue;
			}
			return -1;
		}
		p+=n;
		left-=n;
	}
	return len;
}
//采集本机外接外设(USB 设备 + PCI 设备)及其版本
//USB: 遍历 /sys/bus/usb/devices/,读 idVendor/idProduct 拼 VID:PID,读 bcdDevice 当固件版本
//PCI: 遍历 /sys/bus/pci/devices/,目录名即 BDF,版本读绑定驱动模块的 modinfo
//names[i]  = 设备稳定标识(USB="VID:PID",PCI="BDF")
//vers[i]   = 版本号(USB 固件 bcdDevice / PCI 驱动版本),读不到记 unknown
//返回值:实际采集到的外设数量
int collect_local_devices(char names[][50],char vers[][50],int max)
{
	int n=0;
	//---------- USB 外设 ----------
	DIR* udp=opendir("/sys/bus/usb/devices/");
	if(udp!=NULL)
	{
		struct dirent* ep;
		while((ep=readdir(udp))!=NULL && n<max)
		{
			if(ep->d_name[0]=='.') continue;
			char base[160];
			snprintf(base,sizeof(base),"/sys/bus/usb/devices/%s",ep->d_name);
			char path[300];
			//读 idVendor(内容形如 "0x046d")
			char vid[24]="";
			snprintf(path,sizeof(path),"%s/idVendor",base);
			FILE* vf=fopen(path,"r");
			if(vf!=NULL){ if(fgets(vid,sizeof(vid),vf)!=NULL) vid[strcspn(vid,"\r\n")]='\0'; fclose(vf); }
			//读 idProduct
			char pid[24]="";
			snprintf(path,sizeof(path),"%s/idProduct",base);
			FILE* pf=fopen(path,"r");
			if(pf!=NULL){ if(fgets(pid,sizeof(pid),pf)!=NULL) pid[strcspn(pid,"\r\n")]='\0'; fclose(pf); }
			if(vid[0]=='\0'||pid[0]=='\0') continue;//没有这两个文件的是总线/根集线器,跳过
			//去掉 "0x" 前缀
			char* vs=vid;
			if(strncmp(vs,"0x",2)==0) vs+=2;
			char* ps=pid;
			if(strncmp(ps,"0x",2)==0) ps+=2;
			char key[40];
			snprintf(key,sizeof(key),"%s:%s",vs,ps);
			//版本:读 bcdDevice(USB 设备固件版本)
			char ver[50]="unknown";
			snprintf(path,sizeof(path),"%s/bcdDevice",base);
			FILE* bf=fopen(path,"r");
			if(bf!=NULL){ if(fgets(ver,sizeof(ver),bf)!=NULL) ver[strcspn(ver,"\r\n")]='\0'; fclose(bf); }
			snprintf(names[n],50,"%s",key);
			snprintf(vers[n],50,"%s",ver);
			n++;
		}
		closedir(udp);
	}
	//---------- PCI 外设 ----------
	DIR* pdp=opendir("/sys/bus/pci/devices/");
	if(pdp!=NULL)
	{
		struct dirent* ep;
		while((ep=readdir(pdp))!=NULL && n<max)
		{
			if(ep->d_name[0]=='.') continue;
			//目录名形如 0000:00:19.0,取冒号后半段作 BDF
			char bdf[32]="";
			char* colon=strchr(ep->d_name,':');
			if(colon!=NULL) snprintf(bdf,sizeof(bdf),"%s",colon+1);
			else snprintf(bdf,sizeof(bdf),"%s",ep->d_name);
			//版本:读 driver/module 软链 -> modinfo -F version
			char ver[50]="unknown";
			char modpath[300];
			snprintf(modpath,sizeof(modpath),"/sys/bus/pci/devices/%s/driver/module",ep->d_name);
			char modname[128]="";
			ssize_t r=readlink(modpath,modname,sizeof(modname)-1);
			if(r>0)
			{
				modname[r]='\0';
				char* slash=strrchr(modname,'/');
				char cmd[192];
				snprintf(cmd,sizeof(cmd),"modinfo -F version %s 2>/dev/null",(slash!=NULL?slash+1:modname));
				FILE* pp=popen(cmd,"r");
				if(pp!=NULL){ if(fgets(ver,sizeof(ver),pp)!=NULL) ver[strcspn(ver,"\r\n")]='\0'; pclose(pp); }
			}
			snprintf(names[n],50,"%s",bdf);
			snprintf(vers[n],50,"%s",ver);
			n++;
		}
		closedir(pdp);
	}
	return n;
}
void* func(void* p)
{
    int sockfd = *(int *)p;
    while(1)
    {
        struct net_info s;
        int ret = recvn(sockfd,&s, sizeof(s));
        if(ret <= 0)
        {
            printf("链接断开\n");
            break; 
        }
		if(s.type==1)
		{
			printf("%s\n",s.info);
		}
		if(s.type==2)
		{
			printf("%s\n",s.info);
			if(strcmp(s.info,"登录成功")==0)
			{
				islogin=1;
				strcpy(loginUsername,s.username);
			}
			else
			{
				islogin=0;
			}
		}
		if(s.type==3)
		{
			printf("%s\n",s.info);//打印文件列表
		}
		if(s.type==4)//下载相关响应
		{
			if(s.info_len==-3||s.info_len==-5)//可下载列表项
			{
				if(g_file_count<300)
				{
					snprintf(g_file_list[g_file_count],50,"%s",s.info);
					snprintf(g_file_key[g_file_count],50,"%s",s.filename);
					g_file_type[g_file_count]=s.info_len;
					g_file_count++;
				}
				continue;
			}
			if(s.info_len==-4)//列表接收完毕
			{
				printf("%s\n",s.info);
				g_list_ready=1;
				continue;
			}
			if(s.info_len==-1)//错误提示(目录不存在 / 文件不存在)
			{
				printf("%s\n",s.info);
				g_list_ready=1;
				g_download_done=1;
				continue;
			}
			if(s.info_len==-2)//下载完成通知
			{
				printf("%s\n",s.info);
				g_download_done=1;
				continue;
			}
			if(s.info_len==0)//开始包:新建(清空)本地文件
			{
				FILE* fp=fopen(s.filename,"w");
				if(fp==NULL)
				{
					printf("无法创建文件 %s\n",s.filename);
					continue;
				}
				fclose(fp);
				continue;
			}
			//数据包:追写到本地文件
			FILE* fp=fopen(s.filename,"a");
			if(fp==NULL)//fopen 失败时 fwrite(NULL) 会段错误
			{
				printf("无法写入文件 %s\n",s.filename);
				continue;
			}
			fwrite(s.info,1,s.info_len,fp);
			fclose(fp);
		}
		if(s.type==6)
		{
			printf("%s ",s.info);
			printf("\n");
		}
		if(s.type==8)//注销结果
		{
			printf("%s\n",s.info);
			if(strcmp(s.info,"注销成功")==0)
			{
				islogin=0;
				loginUsername[0]='\0';
				printf("账号已注销,程序退出\n");
				close(sockfd);
				exit(0);
			}
		}
		if(s.type==9)//驱动版本检测结论
		{
			if(s.info_len==-1)//本批检测的开始包,重置计数
			{
				g_check_recv=0;
				g_check_update=0;
				g_check_newest=0;
				g_check_unknown=0;
				printf("%s\n",s.info);
			}
			else
			{
				g_check_recv++;
				if(s.info_len==1)//版本库未收录,不逐条打印,只计数
				{
					g_check_unknown++;
				}
				else
				{
					if(s.info_len==3) g_check_update++;
					else if(s.info_len==0) g_check_newest++;
					printf("%s\n",s.info);
				}
				if(g_check_total>0&&g_check_recv>=g_check_total)//全部检测完毕,打印汇总
				{
					printf("检测完成:共 %d 个驱动,可更新 %d 个,已是最新 %d 个,版本库未收录 %d 个\n",
						g_check_total,g_check_update,g_check_newest,g_check_unknown);
					g_check_total=0;
				}
			}
		}
    }
}

int main(int argc, char* argv[])
{
    //./send 127.0.0.1 8888
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	printf("%d\n", sockfd);
    
    //准被对方的ip地址和端口号
    struct sockaddr_in youraddr;
	youraddr.sin_family = AF_INET;
	youraddr.sin_port = htons(atoi(argv[2]));//对方的端口号
	youraddr.sin_addr.s_addr = inet_addr(argv[1]);//对方的ip地址
    
    //链接
    int ret = connect(sockfd, (struct sockaddr*)&youraddr, sizeof(youraddr));
    printf("connect %d\n", ret);
    
    pthread_t id;
    pthread_create(&id, NULL, func, &sockfd);
    
    //发送
    while(1)
    {	
        struct net_info s;
		memset(&s,0,sizeof(s));//清空,避免把未初始化的栈内存发送给服务器
		printf("\n1.register 2.login 3.list(本机外设清单) 4.get(下载外设清单/驱动包) 5.put(上传本机外设清单) 6.history 7. exit 8.delete(注销) 9.check update(外设驱动检测)\n");
		printf("please input your chose\n");
        if(scanf("%d",&s.type)!=1)//输入的不是数字,清空输入缓冲后重新选择
		{
			while(getchar()!='\n');
			printf("输入有误,请重新输入\n");
			continue;
		}
        if(s.type==1)
        {
            printf("please input your username and password\n");
			scanf("%s%s",s.username,s.password);
        }
		if(s.type==2)
		{
			printf("please input username and password to login in \n");
			scanf("%s%s",s.username,s.password);
		}
		if(s.type==3)
		{
			//列出当前系统外接外设(USB/PCI)及其版本/固件
			//纯本机采集(遍历 /sys/bus/usb/devices 与 /sys/bus/pci/devices),不需要发给服务器
			char names[300][50];
			char vers[300][50];
			int total=collect_local_devices(names,vers,300);
			if(total<=0)
			{
				printf("未采集到本机外设信息(需要 Linux 环境且能读取 /sys/bus)\n");
				continue;
			}
			printf("本机共采集到 %d 个外设:\n",total);
			printf("%-24s %s\n","设备ID(VID:PID/BDF)","版本/固件");
			//同时保存成文件,方便用选项 5(put) 上传到服务器存档
			FILE* lf=fopen(DEVICE_LIST_FILE,"w");
			if(lf==NULL)
			{
				printf("警告:无法创建 %s,列表只能显示在屏幕上,无法上传\n",DEVICE_LIST_FILE);
			}
			else
			{
				fprintf(lf,"%-24s %s\n","设备ID(VID:PID/BDF)","版本/固件");
			}
			int i;
			for(i=0;i<total;i++)
			{
				printf("%-24s %s\n",names[i],vers[i]);
				if(lf!=NULL)
				{
					fprintf(lf,"%-24s %s\n",names[i],vers[i]);
				}
			}
			if(lf!=NULL)
			{
				fclose(lf);
				printf("已保存到 %s,可用选项 5(put) 上传\n",DEVICE_LIST_FILE);
			}
			continue;//本地查询,不发包给服务器
		}
		if(s.type==4)
		{
			if(islogin==0)
			{
				printf("请先登录\n");
				continue;
			}
			//1.先向服务端请求"我已上传的驱动列表"
			strcpy(s.username,loginUsername);
			s.info_len=-3;//-3=请求列出可下载文件
			g_file_count=0;
			g_list_ready=0;
			sendn(sockfd,&s,sizeof(s));
			//2.等接收线程把列表收完(最多等 3 秒,避免服务端不响应时死等)
			int waited=0;
			while(g_list_ready==0&&waited<3000)
			{
				usleep(10000);//10ms
				waited+=10;
			}
			if(g_file_count<=0)
			{
				printf("没有可下载的内容:请先用选项 5 上传驱动,或确认版本库的驱动包已放到服务器上\n");
				continue;
			}
			//3.显示列表,让用户选一个
			printf("可下载的内容:\n");
			int i;
			for(i=0;i<g_file_count;i++)
			{
				printf("%3d. %-38s %s\n",i+1,g_file_list[i],
					(g_file_type[i]==-5)?"[版本库]":"[我上传的]");
			}
			printf("请输入要下载的编号(如 1)或名称:\n");
			char sel[50];
			scanf("%49s",sel);
			int idx=-1;
			if(sel[0]>='0'&&sel[0]<='9')//输入的是编号
			{
				idx=atoi(sel)-1;
			}
			else//输入的是文件名或驱动名
			{
				for(i=0;i<g_file_count;i++)
				{
					if(strcmp(g_file_key[i],sel)==0||strcmp(g_file_list[i],sel)==0)
					{
						idx=i;
						break;
					}
				}
			}
			if(idx<0||idx>=g_file_count)
			{
				printf("选择无效,请检查编号或名称\n");
				continue;
			}
			//4.发起下载,文件数据由接收线程保存到本地
			memset(&s,0,sizeof(s));
			s.type=4;
			strcpy(s.username,loginUsername);
			snprintf(s.filename,sizeof(s.filename),"%s",g_file_key[idx]);
			s.info_len=(g_file_type[idx]==-5)?-5:0;//-5=版本库驱动包, 0=我上传的文件
			sendn(sockfd,&s,sizeof(s));
			continue;
		}
		if(s.type==5)
		{
			if(islogin==0)
			{
				printf("请先登录\n");
				continue;
			}
			//上传本机外设清单:先采集全部外设,写成 device_list.txt,再把这个文件上传到服务器存档
			char names[300][50];
			char vers[300][50];
			int total=collect_local_devices(names,vers,300);
			if(total<=0)
			{
				printf("未采集到本机外设信息,无法上传\n");
				continue;
			}
			FILE* lf=fopen(DEVICE_LIST_FILE,"w");
			if(lf==NULL)
			{
				printf("无法创建外设清单文件\n");
				continue;
			}
			int i;
			for(i=0;i<total;i++)
			{
				fprintf(lf,"%-24s %s\n",names[i],vers[i]);
			}
			fclose(lf);
			printf("已生成外设清单 %s(共 %d 个设备),开始上传...\n",DEVICE_LIST_FILE,total);
			FILE* fp=fopen(DEVICE_LIST_FILE,"rb");
			if(fp==NULL)
			{
				printf("无法打开清单文件 %s\n",DEVICE_LIST_FILE);
				continue;
			}
			strcpy(s.username,loginUsername);
			//清单文件名固定为 device_list.txt(在用户目录下)
			strcpy(s.filename,DEVICE_LIST_FILE);
			s.info_len=-1;//开始包:通知服务端新建(清空)这个文件
			sendn(sockfd,&s,sizeof(s));
			s.info_len=fread(s.info,1,sizeof(s.info),fp);
			while(s.info_len>0)
			{
				sendn(sockfd,&s,sizeof(s));
				s.info_len=fread(s.info,1,sizeof(s.info),fp);
				usleep(100);
			}
			fclose(fp);
			printf("外设清单已上传,服务器保存为 %s\n",s.filename);
			sleep(1);//给接收线程留时间打印提示,避免菜单插在结果前面
			continue;
		}
		if(s.type==6)
		{
			if(islogin==0)
			{
				printf("请先登录\n");
				continue;
			}
			strcpy(s.username,loginUsername);
		}
		if(s.type==7)
		{
			printf("退出\n");
			close(sockfd);
			exit(0);
		}
		if(s.type==8)//注销账号
		{
			if(islogin==1)
			{
				printf("注销将删除账号及全部文件,请输入密码确认:\n");
				scanf("%s",s.password);
				strcpy(s.username,loginUsername);
			}
			else
			{
				printf("请先登录\n");
				continue;
			}
		}
		if(s.type==9)//外设驱动检测:采集本机外设后批量上报
		{
			if(islogin==0)
			{
				printf("请先登录\n");
				continue;
			}
			char names[300][50];
			char vers[300][50];
			int total=collect_local_devices(names,vers,300);
			if(total<=0)
			{
				printf("未采集到本机外设信息\n");
				continue;
			}
			g_check_total=total;
			printf("本机共采集到 %d 个外设,正在检测...\n",total);
			memset(&s,0,sizeof(s));
			s.type=9;
			s.info_len=-1;//开始包:通知服务器重置并记录一条历史
			strcpy(s.username,loginUsername);
			sendn(sockfd,&s,sizeof(s));
			usleep(1000);
			int i;
			for(i=0;i<total;i++)//逐条上报设备ID与本机版本
			{
				memset(&s,0,sizeof(s));
				s.type=9;
				s.info_len=0;
				strcpy(s.username,loginUsername);
				strcpy(s.filename,names[i]);
				strcpy(s.info,vers[i]);
				sendn(sockfd,&s,sizeof(s));
				usleep(1000);
			}
			//等服务端返回全部结论(最多 10 秒),让检测结果先打印完再回到菜单
			{
				int wt=0;
				while(g_check_total>0&&g_check_recv<g_check_total&&wt<10000)
				{
					usleep(10000);//10ms
					wt+=10;
				}
			}
			continue;
		}
		sendn(sockfd,&s,sizeof(s));
		sleep(1);
    }
    
	close(sockfd);//关闭socket使用close
}

