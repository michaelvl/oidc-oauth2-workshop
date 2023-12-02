FROM python:3.9.0-buster

RUN pip install --upgrade pip

COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt

COPY client /usr/src/client
COPY idp-auth-server /usr/src/idp-auth-server
COPY protected-api /usr/src/protected-api

EXPOSE 5000

# This container contains all three components, default to client
WORKDIR /usr/src/client/app
CMD ["/usr/src/client/app/client.py"]
ENTRYPOINT ["python"]
