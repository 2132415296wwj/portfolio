#include <sys/types.h>         
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pthread.h>
#include<sqlite3.h>
#include<unistd.h>
#include<string.h>
#include <dirent.h>
#include<time.h>
#include<ctype.h>
#include<stdlib.h>
#include<errno.h>
#include<crypt.h>
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
sqlite3* db;
//生成 len 个随机字符的 salt(字符集 a-zA-Z0-9),取自 /dev/urandom
void make_salt(char* salt,int len)
{
	static const char chars[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	FILE* uf=fopen("/dev/urandom","rb");
	int i;
	for(i=0;i<len;i++)
	{
		unsigned char b=0;
		if(uf!=NULL && fread(&b,1,1,uf)!=1){ b=(unsigned char)(rand()&0xff); }
		salt[i]=chars[b%(int)(sizeof(chars)-1)];
	}
	salt[len]='\0';
	if(uf!=NULL) fclose(uf);
}
//对明文密码做加盐 SHA-512 哈希,out 写入完整哈希串($6$salt$hash),数据库只存它、不存明文
char* hash_password(const char* passwd,char* out,size_t outsz)
{
	char salt[17];
	make_salt(salt,16);
	char setting[32];
	snprintf(setting,sizeof(setting),"$6$%s$",salt);//$6$ = SHA-512
	char* r=crypt(passwd,setting);
	if(r==NULL){ out[0]='\0'; return out; }
	snprintf(out,outsz,"%s",r);
	return out;
}
//校验明文密码是否与已存哈希匹配:算法标记和 salt 都编码在 stored 里,重新哈希后整体比对
int verify_password(const char* passwd,const char* stored)
{
	if(stored==NULL||stored[0]=='\0') return 0;
	char* r=crypt(passwd,stored);
	if(r==NULL) return 0;
	return strcmp(r,stored)==0;
}
void inserthistory(char *username,char*action)
{
	char sql[100];
	time_t t = time(NULL);//获得从1970年1月1日到现在的秒数
	struct tm * tp = localtime(&t);//通过秒数获得年月日时分秒
	char buf[100];
	char*err;
	sprintf(buf, "%d-%d-%d %02d:%02d:%02d",tp->tm_year+1900, tp->tm_mon+1, tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	sprintf(sql,"insert into his_info values('%s','%s','%s');",username,buf,action);
	int ret=sqlite3_exec(db,sql,NULL,NULL,&err);
}
void my_regsiter(int newfd ,struct net_info s)
{
	//1.查重:参数化查询,防止用户名里的特殊字符改变 SQL 语义
	sqlite3_stmt* stmt=NULL;
	int ret=sqlite3_prepare_v2(db,"select 1 from user_info where username=?1;",-1,&stmt,NULL);
	if(ret!=SQLITE_OK)
	{
		printf("[register]:%s\n",sqlite3_errmsg(db));
		return;
	}
	sqlite3_bind_text(stmt,1,s.username,-1,SQLITE_TRANSIENT);
	int found=(sqlite3_step(stmt)==SQLITE_ROW);
	sqlite3_finalize(stmt);
	if(found)
	{
		strcpy(s.info,"注册失败,用户名已存在");
		sendn(newfd,&s,sizeof(s));
		return;
	}
	//2.对明文密码加盐哈希,数据库只存哈希串
	char hash[200];
	hash_password(s.password,hash,sizeof(hash));
	if(hash[0]=='\0')
	{
		strcpy(s.info,"注册失败,服务器内部错误");
		sendn(newfd,&s,sizeof(s));
		return;
	}
	//3.参数化插入账号
	stmt=NULL;
	ret=sqlite3_prepare_v2(db,"insert into user_info(username,passwd) values(?1,?2);",-1,&stmt,NULL);
	if(ret!=SQLITE_OK)
	{
		printf("[register]:%s\n",sqlite3_errmsg(db));
		return;
	}
	sqlite3_bind_text(stmt,1,s.username,-1,SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt,2,hash,-1,SQLITE_TRANSIENT);
	ret=sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if(ret!=SQLITE_DONE)
	{
		strcpy(s.info,"注册失败,数据库写入错误");
		sendn(newfd,&s,sizeof(s));
		return;
	}
	//4.创建同名文件夹存放该用户文件
	pid_t pid=fork();
	if(pid==0)
	{
		execlp("mkdir","mkdir",s.username,NULL);
		_exit(1);
	}
	else if(pid>0)
	{
		wait(NULL);
	}
	strcpy(s.info,"注册成功");
	sendn(newfd,&s,sizeof(s));
}
void my_login(int newfd,struct net_info s)
{
	//1.只按用户名参数化查出已存的密码哈希(不在 SQL 里比对密码)
	sqlite3_stmt* stmt=NULL;
	int ret=sqlite3_prepare_v2(db,"select passwd from user_info where username=?1;",-1,&stmt,NULL);
	if(ret!=SQLITE_OK)
	{
		printf("[login]:%s\n",sqlite3_errmsg(db));
		return;
	}
	sqlite3_bind_text(stmt,1,s.username,-1,SQLITE_TRANSIENT);
	char stored[200]="";
	if(sqlite3_step(stmt)==SQLITE_ROW)
	{
		const char* p=(const char*)sqlite3_column_text(stmt,0);
		if(p!=NULL) snprintf(stored,sizeof(stored),"%s",p);
	}
	sqlite3_finalize(stmt);
	//2.用同样的 salt 重新哈希输入密码,与库中哈希整体比对
	if(stored[0]!='\0' && verify_password(s.password,stored))
	{
		strcpy(s.info,"登录成功");
	}
	else
	{
		strcpy(s.info,"登录失败");
	}
	sendn(newfd,&s,sizeof(s));
}
void my_list(int newfd,struct net_info s)
{
	DIR* dp=opendir(s.username);//打开在登录后所记录的用户名同名文件夹
	if(dp==NULL)//打开失败,没有这个文件夹,与这个文件夹下没有文件是不同的!
	{
		return ;
	}
	struct dirent* ep = readdir(dp);//读取这个文件夹下的文件
	while(ep!=NULL)
	{

		if(ep->d_name[0]!='.')
		{
			strcpy(s.info,ep->d_name);
			sendn(newfd,&s,sizeof(s));
			usleep(100);
		}
		ep=readdir(dp);
	}
	inserthistory(s.username,"list");
}
void my_get(int newfd,struct net_info s)
{
	char file_path[50];
	sprintf(file_path,"%s/%s",s.username,s.filename);
	FILE *fp =fopen(file_path,"r");
	fseek(fp,s.info_len,SEEK_SET);
	s.info_len=fread(s.info,1,sizeof(s.info),fp);
	while(s.info_len>0)
	{
		sendn(newfd,&s,sizeof(s));
		sleep(2);
		printf("%d\n", s.info_len);
		s.info_len=fread(s.info,1,sizeof(s.info),fp);
		usleep(100);
	}
	fclose(fp);
	inserthistory(s.username,"get");
}
void my_put(int newfd,struct net_info s)
{
	char my_path[128];//username(50)+文件名(50)+'/'+'\0' 超过 100 字节,原来只有 50 会栈溢出
	snprintf(my_path,sizeof(my_path),"%s/%s",s.username,s.filename);
	if(s.info_len==-1)//开始包:清空(创建)目标文件
	{
		FILE* fp=fopen(my_path,"w");
		if(fp==NULL)//用户目录不存在或权限不足
		{
			printf("[put]:无法创建 %s\n",my_path);
			return;
		}
		fclose(fp);
		inserthistory(s.username,"put");
		return;
	}
	if(s.info_len>0)//数据包:追加写入
	{
		FILE* fp=fopen(my_path,"a");
		if(fp==NULL)//fopen 失败时 fwrite/fclose(NULL) 会让服务端段错误
		{
			printf("[put]:无法写入 %s\n",my_path);
			return;
		}
		fwrite(s.info,1,s.info_len,fp);
		fclose(fp);
	}
}
//下载指定驱动(type=4):按版本库中记录的 pkg_path 把驱动包下发给客户端
//请求:s.filename=驱动名
//响应:info_len=0 开始包(filename 为客户端要保存的文件名) / >0 数据包 / -1 错误提示 / -2 下载完成
void my_get_driver(int newfd,struct net_info s)
{
	char drv[50]="";
	snprintf(drv,sizeof(drv),"%s",s.filename);
	sqlite3_stmt* stmt=NULL;
	int ret=sqlite3_prepare_v2(db,"select version,pkg_path from driver_info where name=?1;",-1,&stmt,NULL);
	if(ret!=SQLITE_OK)
	{
		printf("[get-driver]:%s\n",sqlite3_errmsg(db));
		s.info_len=-1;
		snprintf(s.info,sizeof(s.info),"下载失败,服务器内部错误");
		sendn(newfd,&s,sizeof(s));
		return;
	}
	sqlite3_bind_text(stmt,1,drv,-1,SQLITE_TRANSIENT);
	if(sqlite3_step(stmt)!=SQLITE_ROW)//版本库没有收录这个驱动
	{
		sqlite3_finalize(stmt);
		s.info_len=-1;
		snprintf(s.info,sizeof(s.info),"版本库未收录驱动 %s",drv);
		sendn(newfd,&s,sizeof(s));
		return;
	}
	char version[50]="";
	char pkg[200]="";
	const char* p=(const char*)sqlite3_column_text(stmt,0);
	if(p!=NULL)
	{
		snprintf(version,sizeof(version),"%s",p);
	}
	p=(const char*)sqlite3_column_text(stmt,1);
	if(p!=NULL)
	{
		snprintf(pkg,sizeof(pkg),"%s",p);
	}
	sqlite3_finalize(stmt);
	if(pkg[0]=='\0')//版本库里没配驱动包路径
	{
		s.info_len=-1;
		snprintf(s.info,sizeof(s.info),"驱动 %s 未配置驱动包路径(pkg_path 为空)",drv);
		sendn(newfd,&s,sizeof(s));
		return;
	}
	FILE* fp=fopen(pkg,"rb");
	if(fp==NULL)//服务器上没有这个驱动包文件
	{
		s.info_len=-1;
		snprintf(s.info,sizeof(s.info),"驱动 %s(%s) 的驱动包不存在:%s",drv,version,pkg);
		sendn(newfd,&s,sizeof(s));
		return;
	}
	snprintf(s.filename,sizeof(s.filename),"%s-%s.bin",drv,version);//客户端保存的文件名
	s.info[0]='\0';
	s.info_len=0;//开始包:通知客户端新建文件
	sendn(newfd,&s,sizeof(s));
	int n;
	while((n=fread(s.info,1,sizeof(s.info),fp))>0)
	{
		s.info_len=n;
		sendn(newfd,&s,sizeof(s));
		usleep(100);
	}
	fclose(fp);
	s.info_len=-2;//下载完成通知
	snprintf(s.info,sizeof(s.info),"驱动 %s %s 下载完成,已保存为 %s",drv,version,s.filename);
	sendn(newfd,&s,sizeof(s));
	inserthistory(s.username,"get-driver");
}
//下载自己上传到服务器的驱动(type=4)
//请求:info_len=-3 列出可下载文件 / info_len=0 下载 s.filename 指定的文件
//响应:info_len=-3 列表项 / -4 列表结束 / -1 错误提示 / 0 开始包 / >0 数据包 / -2 下载完成
void my_get_file(int newfd,struct net_info s)
{
	if(s.info_len==-3)//列出可下载内容:我上传的 + 版本库驱动包
	{
		int cnt=0;
		//1.我上传的驱动(在用户目录下)
		DIR* dp=opendir(s.username);
		if(dp!=NULL)
		{
			struct dirent* ep;
			while((ep=readdir(dp))!=NULL)
			{
				if(ep->d_name[0]=='.')//跳过 . .. 和隐藏文件
				{
					continue;
				}
				snprintf(s.info,sizeof(s.info),"%s",ep->d_name);
				snprintf(s.filename,sizeof(s.filename),"%s",ep->d_name);
				s.info_len=-3;//我上传的文件
				sendn(newfd,&s,sizeof(s));
				cnt++;
				usleep(50);
			}
			closedir(dp);
		}
		//2.版本库里的驱动包(只列服务器上真实存在文件的,避免选了却下不到)
		sqlite3_stmt* stmt=NULL;
		int ret=sqlite3_prepare_v2(db,"select name,version,pkg_path from driver_info;",-1,&stmt,NULL);
		if(ret==SQLITE_OK)
		{
			while(sqlite3_step(stmt)==SQLITE_ROW)
			{
				const char* n=(const char*)sqlite3_column_text(stmt,0);
				const char* v=(const char*)sqlite3_column_text(stmt,1);
				const char* p=(const char*)sqlite3_column_text(stmt,2);
				if(n==NULL||p==NULL||p[0]=='\0')
				{
					continue;
				}
				FILE* tf=fopen(p,"rb");
				if(tf==NULL)//驱动包文件不存在,不列出
				{
					continue;
				}
				fclose(tf);
				snprintf(s.filename,sizeof(s.filename),"%s",n);//下载标识=驱动名
				snprintf(s.info,sizeof(s.info),"%s %s",n,(v!=NULL?v:""));
				s.info_len=-5;//版本库驱动包
				sendn(newfd,&s,sizeof(s));
				cnt++;
				usleep(50);
			}
			sqlite3_finalize(stmt);
		}
		s.info_len=-4;//列表结束
		if(cnt==0)
		{
			snprintf(s.info,sizeof(s.info),"暂无可下载内容:先用选项 5 上传本机外设清单,或把外设驱动包放到版本库配置的路径上");
		}
		else
		{
			snprintf(s.info,sizeof(s.info),"共 %d 项",cnt);
		}
		sendn(newfd,&s,sizeof(s));
		return;
	}
	if(s.info_len==-5)//下载版本库里的驱动包(复用已有的 my_get_driver)
	{
		my_get_driver(newfd,s);
		return;
	}
	//下载指定文件:从该用户的目录下取
	char path[128];//原来 50 字节存不下 用户名+文件名,会溢出
	snprintf(path,sizeof(path),"%s/%s",s.username,s.filename);
	FILE* fp=fopen(path,"rb");
	if(fp==NULL)
	{
		s.info_len=-1;
		snprintf(s.info,sizeof(s.info),"文件不存在:%s",s.filename);
		sendn(newfd,&s,sizeof(s));
		return;
	}
	s.info[0]='\0';
	s.info_len=0;//开始包:通知客户端新建文件
	sendn(newfd,&s,sizeof(s));
	int n;
	while((n=fread(s.info,1,sizeof(s.info),fp))>0)
	{
		s.info_len=n;
		sendn(newfd,&s,sizeof(s));
		usleep(100);
	}
	fclose(fp);
	s.info_len=-2;//下载完成
	snprintf(s.info,sizeof(s.info),"文件 %s 下载完成",s.filename);
	sendn(newfd,&s,sizeof(s));
	inserthistory(s.username,"get");
}
void my_history(int newfd,struct net_info s)
{
	char sql[100];
	sprintf(sql,"select *  from his_info where username='%s';",s.username);
	char**q;
	char *err;
	int nrow,ncol;
	int ret=sqlite3_get_table(db,sql,&q,&nrow,&ncol,&err);
	if(ret==SQLITE_OK)
	{
		if(nrow==0)
		{
			strcpy(s.info,"没查询到内容");
			sendn(newfd,&s,sizeof(s));
		}
		else
		{
			int i,j;
			for(i=0;i<nrow+1;i++)
			{
				sprintf(s.info,"%s %s %s",q[i*3],q[i*3+1],q[i*3+2]);
				sendn(newfd,&s,sizeof(s));
				usleep(100);
			}
		}
	}
	else
	{
		printf("[%s]:%s\n",sql,err);
	}
	inserthistory(s.username,"list");
}
//版本比较:按 '.' '-' '_' 分段,数字段按数值比较,非数字段按字符比较
//返回值:1 表示 a 新于 b,-1 表示 a 旧于 b,0 表示两者相同
int compare_version(const char* a,const char* b)
{
	const char* pa=a;
	const char* pb=b;
	while(*pa!='\0'||*pb!='\0')
	{
		while(*pa=='.'||*pa=='-'||*pa=='_') pa++;//跳过分隔符
		while(*pb=='.'||*pb=='-'||*pb=='_') pb++;
		if(*pa=='\0'&&*pb=='\0')
		{
			break;
		}
		if(isdigit((unsigned char)*pa)&&isdigit((unsigned char)*pb))
		{
			char* ea=NULL;
			char* eb=NULL;
			long na=strtol(pa,&ea,10);
			long nb=strtol(pb,&eb,10);
			if(na!=nb)
			{
				return na>nb?1:-1;
			}
			pa=ea;
			pb=eb;
		}
		else//有一侧不是数字,逐字符比较
		{
			if(*pa!=*pb)
			{
				return *pa>*pb?1:-1;
			}
			if(*pa!='\0') pa++;
			if(*pb!='\0') pb++;
		}
	}
	return 0;
}
//驱动版本检测(type=9):客户端上报驱动名与本机版本,与版本库比对后返回结论
//请求:s.filename=驱动名 s.info=本机版本 s.info_len=-1 表示这一批检测的开始包
//响应:s.info=结论文本 s.info_len=0 已是最新 /1 版本库未收录 /2 本机版本未知 /3 有更新 /4 本机版本高于版本库
void my_check_update(int newfd,struct net_info s)
{
	if(s.info_len==-1)//一批检测的开始包:只记一条历史,不参与比较
	{
		inserthistory(s.username,"check-update");
		snprintf(s.info,sizeof(s.info),"开始检测本机驱动版本");
		sendn(newfd,&s,sizeof(s));
		return;
	}
	sqlite3_stmt* stmt=NULL;
	int ret=sqlite3_prepare_v2(db,"select version,changelog from driver_info where name=?1;",-1,&stmt,NULL);
	if(ret!=SQLITE_OK)
	{
		printf("[check]:%s\n",sqlite3_errmsg(db));
		strcpy(s.info,"检测失败,服务器内部错误");
		s.info_len=2;
		sendn(newfd,&s,sizeof(s));
		return;
	}
	sqlite3_bind_text(stmt,1,s.filename,-1,SQLITE_TRANSIENT);
	if(sqlite3_step(stmt)!=SQLITE_ROW)//版本库中没有收录这个驱动
	{
		sqlite3_finalize(stmt);
		s.info_len=1;
		snprintf(s.info,sizeof(s.info),"未收录,%s",s.filename);
		sendn(newfd,&s,sizeof(s));
		return;
	}
	char latest[100]="";
	char note[200]="";
	const char* p=(const char*)sqlite3_column_text(stmt,0);
	if(p!=NULL)
	{
		snprintf(latest,sizeof(latest),"%s",p);
	}
	p=(const char*)sqlite3_column_text(stmt,1);
	if(p!=NULL)
	{
		snprintf(note,sizeof(note),"%s",p);
	}
	sqlite3_finalize(stmt);

	char cur[100]="";
	snprintf(cur,sizeof(cur),"%s",s.info);
	if(cur[0]=='\0'||strcmp(cur,"unknown")==0)//本机取不到版本,无法比较
	{
		s.info_len=2;
		snprintf(s.info,sizeof(s.info),"[无法识别] %s 本机版本未知,版本库最新 %s",s.filename,latest);
		sendn(newfd,&s,sizeof(s));
		return;
	}
	int cmp=compare_version(cur,latest);
	if(cmp<0)
	{
		s.info_len=3;
		snprintf(s.info,sizeof(s.info),"[可更新] %s %s -> %s %s",s.filename,cur,latest,note);
	}
	else if(cmp>0)
	{
		s.info_len=4;
		snprintf(s.info,sizeof(s.info),"[高于版本库] %s 本机 %s,版本库 %s",s.filename,cur,latest);
	}
	else
	{
		s.info_len=0;
		snprintf(s.info,sizeof(s.info),"[已是最新] %s %s",s.filename,cur);
	}
	sendn(newfd,&s,sizeof(s));
}
//校验用户名是否可以安全地作为服务器上的目录名使用
//返回1=合法 0=非法(可能包含路径分隔符或 . / .. 等,会导致 rm -rf 误删其他目录)
int is_safe_username(const char* name)
{
	if(name==NULL||name[0]=='\0')//空用户名
	{
		return 0;
	}
	if(strlen(name)>=50)//超长用户名,防止截断后被利用
	{
		return 0;
	}
	if(strcmp(name,".")==0||strcmp(name,"..")==0)//rm -rf . 会删掉服务器整个运行目录
	{
		return 0;
	}
	if(strchr(name,'/')!=NULL||strchr(name,'\\')!=NULL||strchr(name,'.')!=NULL)
	{
		return 0;
	}
	return 1;
}
//注销账号:校验密码后,删除用户记录、历史记录和用户文件目录
//返回值:1=注销成功(需要断开连接) 0=注销失败
int my_delete(int newfd,struct net_info s)
{
	//0.删除用户目录前先校验用户名,防止误删服务器上的其它目录
	if(!is_safe_username(s.username))
	{
		strcpy(s.info,"注销失败,用户名不合法");
		sendn(newfd,&s,sizeof(s));
		return 0;
	}
	//1.查出该用户已存的密码哈希,用输入密码重新哈希后比对,防止账号被他人注销
	sqlite3_stmt* stmt=NULL;
	int ret=sqlite3_prepare_v2(db,"select passwd from user_info where username=?1;",-1,&stmt,NULL);
	if(ret!=SQLITE_OK)
	{
		printf("[delete]:%s\n",sqlite3_errmsg(db));
		strcpy(s.info,"注销失败,服务器内部错误");//必须回复,否则客户端会一直阻塞在recv
		sendn(newfd,&s,sizeof(s));
		return 0;
	}
	sqlite3_bind_text(stmt,1,s.username,-1,SQLITE_TRANSIENT);
	char stored[200]="";
	if(sqlite3_step(stmt)==SQLITE_ROW)
	{
		const char* p=(const char*)sqlite3_column_text(stmt,0);
		if(p!=NULL) snprintf(stored,sizeof(stored),"%s",p);
	}
	sqlite3_finalize(stmt);
	stmt=NULL;
	if(stored[0]=='\0'||!verify_password(s.password,stored))//账号不存在或密码不对
	{
		strcpy(s.info,"注销失败,用户名或密码错误");
		sendn(newfd,&s,sizeof(s));
		return 0;
	}
	//2.删除该用户的历史记录
	ret=sqlite3_prepare_v2(db,"delete from his_info where username=?1;",-1,&stmt,NULL);
	if(ret==SQLITE_OK)
	{
		sqlite3_bind_text(stmt,1,s.username,-1,SQLITE_TRANSIENT);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		stmt=NULL;
	}
	else
	{
		printf("[delete]:%s\n",sqlite3_errmsg(db));
	}
	//3.删除该用户的账号记录
	ret=sqlite3_prepare_v2(db,"delete from user_info where username=?1;",-1,&stmt,NULL);
	if(ret==SQLITE_OK)
	{
		sqlite3_bind_text(stmt,1,s.username,-1,SQLITE_TRANSIENT);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		stmt=NULL;
	}
	else
	{
		printf("[delete]:%s\n",sqlite3_errmsg(db));
	}
	//4.删除该用户的文件目录(参数化执行,避免命令注入)
	pid_t pid=fork();
	if(pid==0)
	{
		execlp("rm","rm","-rf","--",s.username,NULL);
		_exit(1);
	}
	else if(pid>0)
	{
		wait(NULL);
	}
	else//fork失败,目录未清理
	{
		printf("[delete]:fork failed\n");
		strcpy(s.info,"注销成功,但文件目录清理失败,请管理员手动删除");
		sendn(newfd,&s,sizeof(s));
		return 1;
	}
	//5.返回注销成功并通知断开连接
	strcpy(s.info,"注销成功");
	sendn(newfd,&s,sizeof(s));
	return 1;
}
void* func(void* p)
{
	int newfd = *(int *)p;//将进程中的newfd的值取出，保存到线程 栈区的变量里
	while(1)
	{
		//5.收数据
		struct net_info s;
    	int ret = recvn(newfd,&s, sizeof(s));
    	if(ret <= 0)
    	{
    		printf("链接断开\n");
    		break;
    	}
		printf("type is %d\n",s.type);
		if(s.type==1)//注册
		{
			my_regsiter(newfd,s);
		}
		if(s.type==2)//登录
		{
			my_login(newfd,s);
		}
		if(s.type==3)//list
		{
			my_list(newfd,s);
		}
		if(s.type==4)//下载自己上传的驱动
		{
			my_get_file(newfd,s);
		}
		if(s.type==5)
		{
			my_put(newfd,s);
		}
		if(s.type==6)
		{
			my_history(newfd,s);
		}
		if(s.type==8)//注销账号
		{
			if(my_delete(newfd,s)==1)//注销成功,断开该连接
			{
				break;
			}
		}
		if(s.type==9)//驱动版本检测
		{
			my_check_update(newfd,s);
		}
	}
	close(newfd);//链接通道关闭
}

int main()
{
    //1.创建
   	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int sqlret=sqlite3_open("netdisk.db",&db); 
    char* init_err=NULL;
    //启动时自动建表,表已存在则跳过,不影响已有数据
    //user_info:用户账号(注册/登录/注销校验用)
    //his_info :历史操作记录(注册/登录/注销/检测等动作)
    //driver_info:驱动版本库(供"检测更新"比对版本号)
    const char* init_sql=
        "create table if not exists user_info("
        "username varchar(50),"//用户名(唯一性由注册时查重保证)
        "passwd   text);"//密码:存加盐SHA-512哈希串($6$salt$hash),不存明文
        "create table if not exists his_info("
        "username varchar(50),"//操作人
        "his_time varchar(50),"//操作时间,格式 yyyy-mm-dd hh:mm:ss
        "action   varchar(50));"//操作类型,如 register/login/check-update
        "create table if not exists driver_info("
        "name         text primary key,"//设备标识:USB=VID:PID,PCI=BDF
        "vendor       text,"            //厂商
        "version      text,"            //版本库中的最新版本号
        "release_date text,"            //发布日期
        "changelog    text,"            //更新说明
        "pkg_path     text);";          //驱动包在服务器上的路径(暂未使用)
    int init_ret=sqlite3_exec(db,init_sql,NULL,NULL,&init_err);
    if(init_ret!=SQLITE_OK)
    {
        printf("[init]:%s\n",init_err);
    }
    //2.绑定
    struct sockaddr_in myaddr;
	myaddr.sin_family = AF_INET;//固定的 代表使用ipv4
	myaddr.sin_port = htons(8889);//端口号取值范围是0-65535 short类型
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);//自动识别本机ip地址
	int ret = bind(sockfd, (struct sockaddr *)&myaddr, sizeof(myaddr));
    printf("bind %d\n", ret);
    
    //3.设置监听
    listen(sockfd, 5);
    
    //4.阻塞等待客户端链接
    while(1)
    {
        int newfd = accept(sockfd, NULL, NULL);
    	printf("newfd %d\n", newfd);
    	pthread_t id;
    	pthread_create(&id, NULL, func, &newfd);//将newfd作为参数传进去
    }
    
    //6.关闭
    close(sockfd);
}

