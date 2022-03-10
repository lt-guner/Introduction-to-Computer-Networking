# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select

min_time = float("inf")
max_time = 0
total_time = 0
max_hops = 30
time_out = 2
address = ''
timespent = 0
none_lost_packages = 0


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #


class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""  # Remote Host
        __destinationIpAddress = ""  # Remote Host IP Address
        __header = b''  # Header after byte packing
        __data = b''  # Data after encoding
        __dataRaw = ""  # Raw string data before encoding
        __icmpType = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 1
        __ttl = 255  # Time to live

        __DEBUG_IcmpPacket = False # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def getDestIP(self):
            return self.__destinationIpAddress

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setTimeOut(self, timeout):
            self.__ipTimeout

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)  # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum  # Rotate and add

            answer = ~checksum  # Invert bits
            answer = answer & 0xffff  # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()  # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()  # packHeader() and encodeData() transfer data to their respective bit
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()  # Result will set new checksum value
            self.__packHeader()  # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):

            # show debug messages for the identifier, sequence number, and data
            if self.__DEBUG_IcmpPacket:
                print(f'        Expected ICMP Identifier: {self.getPacketIdentifier()}')
                print(f'        Actual ICMP Identifier: {icmpReplyPacket.getIcmpIdentifier()}')
                print("        Idendifier Valid: ", "True" if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier() else "False")
                print(f'        Expected ICMP Sequence Number: {self.getPacketSequenceNumber()}')
                print(f'        Actual ICMP Sequence Number: {icmpReplyPacket.getIcmpSequenceNumber()}')
                print("        Sequence Number Valid: ", "True" if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber() else "False")
                print(f'        Expected ICMP Data: {self.getDataRaw()}')
                print(f'        Actual ICMP Sequence Number: {icmpReplyPacket.getIcmpData()}')
                print("        Sequence Number Valid: ", "True" if self.getDataRaw() == icmpReplyPacket.getIcmpData() else "False")

            # checks to see if the sequence number, packet number and raw data match the response and if not proceed
            if ((self.getPacketSequenceNumber() != icmpReplyPacket.getIcmpSequenceNumber()) or (
                    self.getPacketIdentifier() != icmpReplyPacket.getIcmpIdentifier()) or (
                    self.getDataRaw() != icmpReplyPacket.getIcmpData())):

                # if the packet ids do not match then set the get valid to false and update the identifier
                if self.getPacketIdentifier() != icmpReplyPacket.getIcmpIdentifier():
                    icmpReplyPacket.setIcmpIdentifier_isValid(False)
                    icmpReplyPacket.setIcmpIdentifier(self.getPacketIdentifier())

                # if the sequence ids do not match then set the get valid to false and update the sequence id
                if self.getPacketSequenceNumber() != icmpReplyPacket.getIcmpSequenceNumber():
                    icmpReplyPacket.setIcmpSequenceNumber_isValid(False)
                    icmpReplyPacket.setIcmpSequenceNumber(self.getPacketSequenceNumber())

                # if the raw data do not match then set the get valid to false and update the raw data
                if self.getDataRaw() != icmpReplyPacket.getIcmpData():
                    icmpReplyPacket.setIcmpData_isValid(False)
                    icmpReplyPacket.setIcmpData(self.getDataRaw())

                icmpReplyPacket.setIsValidResponse(False)

            # else return true to sent is valid
            else:
                icmpReplyPacket.setIsValidResponse(True)
            pass

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, traceroute=0):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            if traceroute == 0:
                print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes

            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received

                # save the current route address for the traceroute
                global address
                address = addr[0]

                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                # save the time spent RTT for the current ping in tracerroute
                global timespent
                timespent = (timeReceived - pingStartTime) * 1000

                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]

                    # update the min_time
                    global min_time
                    if min_time > (timeReceived - timeSent) * 1000:
                        min_time = (timeReceived - timeSent) * 1000

                    # update the max_time
                    global max_time
                    if max_time < (timeReceived - timeSent) * 1000:
                        max_time = (timeReceived - timeSent) * 1000

                    # update the total time
                    global total_time
                    total_time += (timeReceived - timeSent) * 1000

                    # ----------User for testing the function-----------------------------------------------------
                    # icmpType = 3
                    # icmpCode = 11
                    # --------------------------------------------------------------------------------------------

                    if traceroute == 0:
                        global none_lost_packages # track none lost packages
                        # when icmpType retrieved is not 0 then display the messages
                        if icmpType > 0:
                            self.printIcmpMessage(icmpType, icmpCode, ((timeReceived - pingStartTime) * 1000), addr[0])
                            none_lost_packages += 1 # update successful packages
                        elif icmpType == 0:  # Echo Reply
                            icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                            self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                            icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                            none_lost_packages += 1 # update successful packages
                            return  # Echo reply is the end and therefore should return
                        else:
                            print("error")

            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()
                # return address and time spent for user in the trace route
                return (address, timespent)

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i + 1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

        def printIcmpMessage(self, icmpType, icmpCode, rtt, addr):
            """
            This function will prints the Icmp Type and Icmp Code when the Icmp Type retrieved in sendEchoRequest  is not 0
            """

            if icmpType == 1:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Unassigned')
                return

            if icmpType == 2:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Unassigned')
                return

            if icmpType == 3:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Destination Unreachable')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: Net Unreachable')
                    return
                if icmpCode == 1:
                    print(f'  ICMP Code {icmpCode}: Host Unreachable')
                    return
                if icmpCode == 2:
                    print(f'  ICMP Code {icmpCode}: Protocol Unreachable')
                    return
                if icmpCode == 3:
                    print(f'  ICMP Code {icmpCode}: Port Unreachable')
                    return
                if icmpCode == 4:
                    print(f'  ICMP Code {icmpCode}: Fragmentation Needed and Don\'t Fragment was Set')
                    return
                if icmpCode == 5:
                    print(f'  ICMP Code {icmpCode}: Source Route Failed')
                    return
                if icmpCode == 6:
                    print(f'  ICMP Code {icmpCode}: Destination Network Unknown')
                    return
                if icmpCode == 7:
                    print(f'  ICMP Code {icmpCode}: Destination Host Unknown')
                    return
                if icmpCode == 8:
                    print(f'  ICMP Code {icmpCode}: Source Host Isolated')
                    return
                if icmpCode == 9:
                    print(
                        f'  ICMP Code {icmpCode}: Communication with Destination Network is Administratively Prohibited')
                    return
                if icmpCode == 10:
                    print(f'  ICMP Code {icmpCode}: Communication with Destination Host is Administratively Prohibited')
                    return
                if icmpCode == 11:
                    print(f'  ICMP Code {icmpCode}: Destination Network Unreachable for Type of Service')
                    return
                if icmpCode == 12:
                    print(f'  ICMP Code {icmpCode}: Destination Host Unreachable for Type of Service')
                    return
                if icmpCode == 13:
                    print(f'  ICMP Code {icmpCode}: Communication Administratively Prohibited')
                    return
                if icmpCode == 14:
                    print(f'  ICMP Code {icmpCode}: Host Precedence Violation')
                    return
                if icmpCode == 15:
                    print(f'  ICMP Code {icmpCode}: Precedence cutoff in effect')
                    return
                return

            if icmpType == 4:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Source Quench (Deprecated)')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 5:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Redirect')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: Redirect Datagram for the Network (or subnet)')
                    return
                if icmpCode == 1:
                    print(f'  ICMP Code {icmpCode}: Redirect Datagram for the Host')
                    return
                if icmpCode == 2:
                    print(f'  ICMP Code {icmpCode}: Redirect Datagram for the Type of Service and Network')
                    return
                if icmpCode == 3:
                    print(f'  ICMP Code {icmpCode}: Redirect Datagram for the Type of Service and Host')
                    return
                return

            if icmpType == 6:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Alternate Host Address (Deprecated)')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: Alternate Address for Host')
                return

            if icmpType == 7:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Unassigned')
                return

            if icmpType == 8:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Echo')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 9:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Router Advertisement')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: Normal router advertisement')
                    return
                if icmpCode == 16:
                    print(f'  ICMP Code {icmpCode}: Does not route common traffic')
                    return
                return

            if icmpType == 10:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Router Selection')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 11:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Time Exceeded')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: Time to Live exceeded in Transit')
                    return
                if icmpCode == 1:
                    print(f'  ICMP Code {icmpCode}: 	Fragment Reassembly Time Exceeded')
                    return
                return

            if icmpType == 12:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Parameter Problem')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: Pointer indicates the error')
                    return
                if icmpCode == 1:
                    print(f'  ICMP Code {icmpCode}: Missing a Required Option')
                    return
                if icmpCode == 2:
                    print(f'  ICMP Code {icmpCode}: Bad Length')
                    return
                return

            if icmpType == 13:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Timestamp')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 14:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Timestamp Reply')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 15:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Information Request (Deprecated)')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 16:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Information Reply (Deprecated)')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 17:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Address Mask Request (Deprecated)')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 18:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Address Mask Reply (Deprecated)')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Code')
                return

            if icmpType == 19:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Reserved (for Security)')
                return

            if icmpType >= 20 and icmpType <= 29:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Reserved (for Robustness Experiment)')
                return

            if icmpType == 30:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Traceroute (Deprecated)')
                return

            if icmpType == 31:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Datagram Conversion Error (Deprecated)')
                return

            if icmpType == 32:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Mobile Host Redirect (Deprecated)')
                return

            if icmpType == 33:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: IPv6 Where-Are-You (Deprecated)')
                return

            if icmpType == 34:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: IPv6 I-Am-Here (Deprecated)')
                return

            if icmpType == 35:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Mobile Registration Request (Deprecated)')
                return

            if icmpType == 36:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Mobile Registration Reply (Deprecated)')
                return

            if icmpType == 37:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Domain Name Request (Deprecated)')
                return

            if icmpType == 38:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Domain Name Reply (Deprecated)')
                return

            if icmpType == 39:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: SKIP (Deprecated)')
                return

            if icmpType == 40:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Photuris')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: Bad SPI')
                    return
                if icmpCode == 1:
                    print(f'  ICMP Code {icmpCode}: Authentication Failed')
                    return
                if icmpCode == 2:
                    print(f'  ICMP Code {icmpCode}: Decompression Failed')
                    return
                if icmpCode == 3:
                    print(f'  ICMP Code {icmpCode}: Decryption Failed')
                    return
                if icmpCode == 4:
                    print(f'  ICMP Code {icmpCode}: Need Authentication')
                    return
                if icmpCode == 5:
                    print(f'  ICMP Code {icmpCode}: Need Authorization')
                    return
                return

            if icmpType == 41:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(
                    f'  ICMP Type {icmpType}: ICMP messages utilized by experimental mobility protocols such as Seamoby')
                return

            if icmpType == 42:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Extended Echo Request')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Error')
                    return
                if icmpCode >= 1 and icmpCode <= 255:
                    print(f'  ICMP Code {icmpCode}: Unassigned')
                    return
                return

            if icmpType == 43:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Extended Echo Reply')
                if icmpCode == 0:
                    print(f'  ICMP Code {icmpCode}: No Error')
                    return
                if icmpCode == 1:
                    print(f'  ICMP Code {icmpCode}: Malformed Query')
                    return
                if icmpCode == 2:
                    print(f'  ICMP Code {icmpCode}: No Such Interface')
                    return
                if icmpCode == 3:
                    print(f'  ICMP Code {icmpCode}: No Such Table Entry')
                    return
                if icmpCode == 4:
                    print(f'  ICMP Code {icmpCode}: Multiple Interfaces Satisfy Query')
                    return
                if icmpCode >= 5 and icmpCode <= 255:
                    print(f'  ICMP Code {icmpCode}: Unassigned')
                    return
                return

            if icmpType >= 44 and icmpType <= 252:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: Unassigned')
                return

            if icmpType == 253:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: RFC3692-style Experiment 1')
                return

            if icmpType == 254:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" % (
                self.getTtl(), rtt, icmpType, icmpCode, addr))
                print(f'  ICMP Type {icmpType}: RFC3692-style Experiment 2')
                return

            pass

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __icmpIdentifier_isValid = True
        __icmpSequenceNumber_isValid = True
        __icmpData_isValid = True


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):

            # the constructor breaks about the individual data as needed. It also adds duplicates of sequence,
            # identifier, and data that can be used for what was received if the sequence, identifier, and data needed
            # need you be updated
            self.__recvPacket = recvPacket
            self.__icmpType = self.__unpackByFormatAndPositionConstruct("B", 20, recvPacket)
            self.__icmpCode = self.__unpackByFormatAndPositionConstruct("B", 21, recvPacket)
            self.__icmpCheckHeader = self.__unpackByFormatAndPositionConstruct("H", 22, recvPacket)
            self.__icmpIdentifier = self.__unpackByFormatAndPositionConstruct("H", 24, recvPacket)
            self.__icmpSequenceNumber = self.__unpackByFormatAndPositionConstruct("H", 26, recvPacket)
            self.__dateTimeSent = self.__unpackByFormatAndPositionConstruct("d", 28, recvPacket)
            self.__icmpData = recvPacket[36:].decode('utf-8')

            # the duplicate sequence, identifiers, and data
            self.__receivedIcmpIdentifier = self.__unpackByFormatAndPositionConstruct("H", 24, recvPacket)
            self.__receivedIcmpSequenceNumber = self.__unpackByFormatAndPositionConstruct("H", 26, recvPacket)
            self.__receivedIcmpData = recvPacket[36:].decode('utf-8')

            # introducing errors to show how the data is corrected and preserved (uncomment these to test)
            # self.__icmpIdentifier = 1234
            # self.__icmpSequenceNumber = 5678
            # self.__icmpData = "ABCD"
            # self.__receivedIcmpIdentifier = 1234
            # self.__receivedIcmpSequenceNumber = 5678
            # self.__receivedIcmpData = "ABCD"

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            # return self.__unpackByFormatAndPosition("B", 20)

            # Method 3
            return self.__icmpType

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            # return self.__unpackByFormatAndPosition("B", 21)

            # Method 3
            return self.__icmpCode

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            # return self.__unpackByFormatAndPosition("H", 22)

            # Method 3
            return self.__icmpCheckHeader

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            # return self.__unpackByFormatAndPosition("H", 24)

            # Method 3
            return self.__icmpIdentifier

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            # return self.__unpackByFormatAndPosition("H", 26)

            # Method 3
            return self.__icmpSequenceNumber

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            # return self.__unpackByFormatAndPosition("d", 28)  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes

            # Method 2
            return self.__dateTimeSent

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            # return self.__recvPacket[36:].decode('utf-8')

            # Method 2
            return self.__icmpData

        def isValidResponse(self):
            return self.__isValidResponse

        # set and get the for IcmpIdentifier_isValid -----------------------
        def getIcmpIdentifier_isValid(self):
            return self.__icmpIdentifier_isValid

        # get for the IcmpSequenceNumber_isValid ------------------------
        def getIcmpSequenceNumber_isValid(self):
            return self.__icmpSequenceNumber_isValid

        # get for the IcmpData_isValid and original data -----------------------------------
        def getIcmpData_isValidd(self):
            return self.__icmpData_isValid

        # get the original received identifier
        def getReceivedIcmpIdenfier(self):
            return self.__receivedIcmpIdentifier

        # get the original received sequence number
        def getReceivedIcmpSequenceNumber(self):
            return self.__receivedIcmpSequenceNumber

        # get the original received raw data
        def getReceivedIcmpData(self):
            return self.__receivedIcmpData

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # sets identifier is valid or not
        def setIcmpIdentifier_isValid(self, booleanvalue):
            self.__icmpIdentifier_isValid = booleanvalue

        # sets the sequence to is valid or not
        def setIcmpSequenceNumber_isValid(self, booleanvalue):
            self.__icmpSequenceNumber_isValid = booleanvalue

        # sets the data to is valid ot not
        def setIcmpData_isValid(self, booleanvalue):
            self.__icmpData_isValid = booleanvalue

        # set identifier if they are not the same
        def setIcmpIdentifier(self, value):
            self.__icmpIdentifier = value

        # set sequence number if they are not the same as what was sent vs received
        def setIcmpSequenceNumber(self, value):
            self.__icmpSequenceNumber = value

        # set data if they are not the same as what was sent vs received
        def setIcmpData(self, value):
            self.__icmpData = value

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # this function was built to be used in the the init constructor function
        def __unpackByFormatAndPositionConstruct(self, formatCode, basePosition, recvPacket):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, recvPacket[basePosition:basePosition + numberOfbytes])[0]


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):

            if self.isValidResponse() == False:
                if self.getIcmpIdentifier_isValid() == False:
                    print(
                        f'\nEcho Identifier received was \'{self.getReceivedIcmpIdenfier()}\', but it should have been \'{self.getIcmpIdentifier()}\'. It has been updated to \'{self.getIcmpIdentifier()}\'')
                if self.getIcmpSequenceNumber_isValid() == False:
                    print(
                        f'Echo Sequence Number received was \'{self.getReceivedIcmpSequenceNumber()}\', but it should have been \'{self.getIcmpSequenceNumber()}\'. Tf has been updated to \'{self.getIcmpSequenceNumber()}\'')
                if self.getIcmpData_isValidd() == False:
                    print(
                        f'Echo Data received was \'{self.__receivedIcmpData}\', but it should have been \'{self.getIcmpData()}\'. It has been updated to \'{self.getIcmpData()}\'')

            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                  )


    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()  # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        # declare the globals as integers
        global min_time
        min_time = int(round(min_time))
        global max_time
        max_time = int(round(max_time))

        # pages lost
        global none_lost_packages
        packages_lost = (i + 1) - none_lost_packages
        percent_lost_percentage = round(((packages_lost) / (i + 1) * 100),2)

        # calculate avarage time
        global total_time

        if (i + 1 - packages_lost) != 0:
            average_time = round(total_time / (i + 1 - packages_lost))
            # print the results
            print(
                f'Total Stats:     Max RTT = {max_time}ms     Min RTT = {min_time}ms     Average RTT = {average_time}ms    Percent of Lost Packages= {percent_lost_percentage}%\n')

        else:
            print("All packages were lost so there is no data.")

        # wipe out the globals
        max_time = 0
        min_time = float("inf")
        total_time = 0

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here

        # use the global globals for the max time_out and max_hops
        global max_hops
        global time_out

        icmpPacket = IcmpHelperLibrary.IcmpPacket()
        randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
        # Some PIDs are larger than 16 bit

        packetIdentifier = randomIdentifier
        packetSequenceNumber = 1

        icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)
        icmpPacket.setIcmpTarget(host)

        # get the original IP
        destIp = icmpPacket.getDestIP()

        # let the user know that the traceroute has begun
        if host != destIp:
            print(f'Trace Route for URL: {host} IP: {destIp} begins')
        else:
            print(f'Trace Route to : {destIp} begins')

        # increment through the ttl up to max_hops + 1
        for ttl in range(1, max_hops + 1):

            # declare variables for the RTT for each ping
            RTTOne = 0
            RTTTwo = 0
            RTTThree = 0

            # ping the router three times with the ttl and time_out and record each RTT
            for i in range(3):
                icmpPacket.setTtl(ttl)
                icmpPacket.setTimeOut(time_out)
                strresponse = icmpPacket.sendEchoRequest(1)
                if i == 0:
                    RTTOne = int(round(strresponse[1]))
                if i == 1:
                    RTTTwo = int(round(strresponse[1]))
                if i == 2:
                    RTTThree = int(round(strresponse[1]))

            # print the three RTT pings to the current location
            print(
                f'TTL: {ttl}     RTT First Ping: {RTTOne}ms     RTT Second Ping: {RTTTwo}ms     RTT Third Ping: {RTTThree}ms     Current IP Address: {strresponse[0]}')

            # if the destination was reached, let the user know how many hops it took
            if strresponse[0] == destIp:
                if host != destIp:
                    print(f'Trace Route to URL: {host} IP: {destIp} is complete after {ttl} hops')
                else:
                    print(f'Trace Route to IP: {destIp} is complete after {ttl} hops')
                break

        # let the user know the destination was not reached after max_hops
        if ttl == max_hops:
            print(f'The trace is no complete after {max_hops} hops')

        print("\n")

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost, traceroute=0):
        if traceroute == 1:
            pass
        else:
            print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():

    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("www.oregonstate.edu")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("101.0.86.43") # Sydney
    # icmpHelperPing.traceRoute("95.142.107.181") # Amsterdam
    # icmpHelperPing.traceRoute("www.google.com")
    # icmpHelperPing.traceRoute("www.oracle.com")


if __name__ == "__main__":
    main()
