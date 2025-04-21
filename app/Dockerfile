FROM python:3.11-slim


#Говорит интерпретатору не создавать файлы *.pyc
#Отключает буферизацию стандартного вывода и ошибок (stdout, stderr)
ENV PYTHONDONTWRITEBYTECODE=1 \ 
    PYTHONUNBUFFERED=1

#устанавливаем рабочую директорию

WORKDIR /app 

# копируем список зависимостей и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# копируем само приложение
COPY . .


EXPOSE 5000


# запускаем встроенный сервер Flask
CMD ["python", "-u", "main.py"]
