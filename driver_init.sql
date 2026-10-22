-- 数据库初始化脚本
-- 用法(Linux,需在 netdisk.db 所在目录执行): sqlite3 netdisk.db < driver_init.sql
-- 说明: server.c 的 main() 里也会自动执行下面的 create table,
--       本脚本主要用于: ① 从零初始化三张表  ② 导入驱动版本库示例数据
-- 共三张表:
--   user_info    用户账号表(注册 / 登录 / 注销)
--   his_info     历史操作记录表
--   driver_info  外设版本库表(name 必须与客户端采集到的设备标识一致:
--                USB 用 VID:PID(如 046d:c52b),可用 lsusb 查看;PCI 用 BDF(如 00:19.0),可用 lspci 查看)

-- 用户账号表(结构与现有 netdisk.db 一致:无主键,唯一性由注册时查重保证)
create table if not exists user_info(
    username varchar(50), -- 用户名
    passwd   text         -- 密码:存加盐SHA-512哈希串($6$salt$hash),不存明文
);

-- 历史操作记录表
create table if not exists his_info(
    username varchar(50), -- 操作人
    his_time varchar(50), -- 操作时间,格式 yyyy-mm-dd hh:mm:ss
    action   varchar(50)  -- 操作类型,如 register/login/check-update
);

-- 驱动版本库表
create table if not exists driver_info(
    name         text primary key, -- 设备标识:USB=VID:PID,PCI=BDF
    vendor       text,             -- 厂商
    version      text,             -- 版本库中的最新版本号
    release_date text,             -- 发布日期
    changelog    text,             -- 更新说明
    pkg_path     text              -- 驱动包在服务器上的路径(暂未使用)
);

-- 示例数据: 收录常见外接外设的最新驱动/固件版本
-- name 与客户端采集到的设备标识一致: USB 设备用 "VID:PID"(十六进制,不带 0x),PCI 设备用 BDF(如 00:19.0)
-- 可用 lsusb 查看本机 USB 设备的 VID:PID,用 lspci 查看 PCI 设备 BDF
-- 版本号故意高于常见本机版本,便于演示"可更新"
insert or replace into driver_info values('046d:c52b', 'Logitech',  '0112', '2026-08-01', '修复休眠后键鼠断连',       'drivers/046d-c52b/0112');
insert or replace into driver_info values('0bda:0129', 'Realtek',   '61.00', '2026-08-05', '提升读卡器识别稳定性',     'drivers/0bda-0129/61.00');
insert or replace into driver_info values('138a:0090', 'Synaptics', '5.00',  '2026-08-10', '修复指纹偶发识别失败',     'drivers/138a-0090/5.00');
insert or replace into driver_info values('046d:c534', 'Logitech',   '0114', '2026-08-12', 'G Pro 鼠标固件更新',        'drivers/046d-c534/0114');
insert or replace into driver_info values('0bda:568a', 'Realtek',    '5.08',  '2026-08-15', '摄像头暗光优化',            'drivers/0bda-568a/5.08');
insert or replace into driver_info values('0781:5567', 'SanDisk',    '1.00',  '2026-08-18', 'U 盘兼容性更新',            'drivers/0781-5567/1.00');

-- 常用维护命令:
--   查看版本库:  select * from driver_info;
--   改版本号:    update driver_info set version='0113', release_date='2026-09-01' where name='046d:c52b';
--   删除设备:    delete from driver_info where name='046d:c52b';
--   查看检测记录: select * from his_info where action='check-update';
