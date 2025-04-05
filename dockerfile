# 使用 Python 3.10 作为基础镜像
FROM python:3.10-slim

# 设置工作目录
WORKDIR /app

# 复制项目文件
COPY . .

# 设置数据卷挂载点
VOLUME ["/app/config", "/app/logs", "/app/usermanager"]

# 暴露端口
# SMTP 端口
EXPOSE 25
EXPOSE 465
# POP3 端口
EXPOSE 110
EXPOSE 995

# 设置时区为亚洲/上海
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 启动服务器
CMD ["python", "wMailServer.py"]