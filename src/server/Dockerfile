FROM python:latest
COPY server.py /server.py
RUN pip install flask
CMD ["flask", "--app", "server", "run", "--host", "0.0.0.0"]