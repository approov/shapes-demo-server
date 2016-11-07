#!/bin/python

from flask import Flask, request, abort
import jwt
import json
import socket
import base64
import random

"""/*****************************************************************************
     * Project:     ApproovServerDemo
     * File:        runServer.py
     * Original:    Created on 19 Sep 2016
     * Copyright(c) 2002 - 2016 by CriticalBlue Ltd.
     ****************************************************************************/"""

app = Flask(__name__)

# Your Token Secret is generated for you when the Approov service is initialized
# and it can be copied to your server code from your Approov Admin Portal
# Set the secret as base64 encoded constant
SECRET = "<YOUR TOKEN>"

shapes=["Circle","Triangle","Square","Rectangle"]

def verifyToken(token, clientIP):
  try:
    tokenContents = jwt.decode(token, base64.b64decode(SECRET), algorithms=['HS256'])
  except jwt.ExpiredSignatureError:
    # Signature has expired, token is bad
    return 0
  except:
    # Token could not be decoded, token is bad
    return 0

  # Get IP from token contents if present then check it
  try:
    issuedIP = (tokenContents['ip'])

    # Compare the issued IP with the requester IP
    if clientIP != issuedIP:
        # Requester IP did not match issued IP
        return 0
  except:
    # There is no IP claim, we don't need to check it
    pass

  # Token was decoded successfully, token is good
  return 1

@app.route("/")
def returnShape():

  # Get the Approov Token from header
  token = request.headers.get("ApproovToken")

  # If we  didn't find a token, then reject the request
  if token == "":
    abort(400)

  # Get the requesters IP Address as IPv6 for consistency
  clientIP = request.remote_addr
  try:
    clientIPBin = socket.inet_pton(socket.AF_INET6, clientIP)
  except:
    clientIPBin = socket.inet_pton(socket.AF_INET6, "::ffff:"+clientIP)
  clientIPBinBase64 = base64.b64encode(clientIPBin)

  # Now verify the token
  tokenOK = verifyToken(token, clientIPBinBase64)

  if tokenOK != 1:
    # Token is bad
    abort(400)


  return shapes[random.randint(0, len(shapes)-1)]

if __name__ == "__main__":
  app.run(debug=False, host='0.0.0.0', port=5000)
