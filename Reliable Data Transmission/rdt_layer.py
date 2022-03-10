from segment import Segment


# #################################################################################################################### #
# RDTLayer                                                                                                             #
#                                                                                                                      #
# Description:                                                                                                         #
# The reliable data transfer (RDT) layer is used as a communication layer to resolve issues over an unreliable         #
# channel.                                                                                                             #
#                                                                                                                      #
#                                                                                                                      #
# Notes:                                                                                                               #
# This file is meant to be changed.                                                                                    #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #


class RDTLayer(object):
    # ################################################################################################################ #
    # Class Scope Variables                                                                                            #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    DATA_LENGTH = 4 # in characters                     # The length of the string data that will be sent per packet...
    FLOW_CONTROL_WIN_SIZE = 15 # in characters          # Receive window size for flow-control
    sendChannel = None
    receiveChannel = None
    dataToSend = ''
    currentIteration = 0                                # Use this for segment 'timeouts'
    # Add items as needed
    currSegWindow =[0,4]
    currentSeqNum = 0
    expectedAck = 4
    serverDataList = []

    # ################################################################################################################ #
    # __init__()                                                                                                       #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __init__(self):
        self.sendChannel = None
        self.receiveChannel = None
        self.dataToSend = ''
        self.currentIteration = 0
        # Add items as needed
        self.timeoutCount = 0
        self.currAck = 0
        self.windowStart = 0
        self.windowEnd = 4
        self.waitTime = 0

    # ################################################################################################################ #
    # setSendChannel()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable sending lower-layer channel                                                 #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setSendChannel(self, channel):
        self.sendChannel = channel

    # ################################################################################################################ #
    # setReceiveChannel()                                                                                              #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable receiving lower-layer channel                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setReceiveChannel(self, channel):
        self.receiveChannel = channel

    # ################################################################################################################ #
    # setDataToSend()                                                                                                  #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the string data to send                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setDataToSend(self,data):
        self.dataToSend = data

    # ################################################################################################################ #
    # getDataReceived()                                                                                                #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to get the currently received and buffered string data, in order                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def getDataReceived(self):
        # ############################################################################################################ #
        # Identify the data that has been received...
        #print('getDataReceived(): Complete this...')
        sortedData = sorted(self.serverDataList)

        sortedString = ""
        for i in range(len(sortedData)):
            sortedString += sortedData[i][1]
        # ############################################################################################################ #
        return sortedString

    # ################################################################################################################ #
    # processData()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # "timeslice". Called by main once per iteration                                                                   #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processData(self):
        self.currentIteration += 1
        self.processSend()
        self.processReceiveAndSendRespond()

    # ################################################################################################################ #
    # processSend()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment sending tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processSend(self):

        # this will control the timeouts that happen
        # if we have gone an iteration without receing an acknowledgement than proceed
        if (self.currentIteration > 1 and len(self.receiveChannel.receiveQueue) == 0):
            # if we have a an iteration but it has not reached the timeout then increment timeWaited by one and exit
            if self.waitTime != 4:
                self.waitTime += 1
                return
            # else the timeout has been reached and much increment the timeCounted and reset the window
            else:
                self.currentSeqNum = self.currSegWindow[0]
                self.timeoutCount += 1

        # ############################################################################################################ #
        #print('processSend(): Complete this...')
        if(self.dataToSend != ""):
            # create a blank list and the incoming data will be parsed in
            process_list = []
            for index in range(0, len(self.dataToSend), self.DATA_LENGTH):
                process_list.append(self.dataToSend[index: index + self.DATA_LENGTH])

            # pull the data from the receiveQueue
            # if there is ack numbers that match then increment the appropriate fields
            acklist = self.receiveChannel.receive()
            for i in range(0, len(acklist)):
                if acklist[i].acknum == self.expectedAck:
                    self.currentSeqNum += 4
                    self.expectedAck += 4
                    self.currSegWindow[0] += 4
                    self.currSegWindow[1] += 4

            # next we iterate populate the windows we are sending data with front and end starting positions
            self.windowStart = self.currentSeqNum
            self.windowEnd = self.currentSeqNum + 4

            for i in range(self.windowStart, self.windowEnd):
                # make sure the current iteration of is not out of range of the list length
                if (i < len(process_list)):
                    # make the send segment as instructed for each data fragment we are sending
                    segmentSend = Segment()

                    # send the current data segment using sendDate as requested by the instructions
                    segmentSend.setData(i, process_list[i])

                    # four segments are being send and we need to receive some ACK before processing another batch
                    segmentSend.setStartIteration(self.currentIteration)
                    segmentSend.setStartDelayIteration(4)

                    # Use the unreliable sendChannel to send the segment
                    self.sendChannel.send(segmentSend)

        else:
            # next we iterate populate the windows we are sending data with front and end starting positions
            self.windowStart = self.currentSeqNum
            self.windowEnd = self.currentSeqNum + 4
            
        return 

    # ################################################################################################################ #
    # processReceive()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment receive tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processReceiveAndSendRespond(self):

        # This call returns a list of incoming segments (see Segment class)...
        listIncomingSegments = self.receiveChannel.receive()

        # ############################################################################################################ #
        # What segments have been received?
        # How will you get them back in order?
        # This is where a majority of your logic will be implemented
        # print('processReceive(): Complete this...')

        # How do you respond to what you have received?
        # How can you tell data segments apart from ack segemnts?

        # Somewhere in here you will be setting the contents of the ack segments to send.
        # The goal is to employ cumulative ack, just like TCP does...
        # Use the unreliable sendChannel to send the ack packet

        # if there is data in the listIncoming we want to then we do the following
        if len(listIncomingSegments) > 0:
            segmentAck = Segment()  # Segment acknowledging packet(s) received

            # update the expected Ack
            self.expectedAck = self.currSegWindow[1]

            # get what is in the payload wit the seqnum in a payload list
            payloadAndSeqnum = []
            for i in range(0, len(listIncomingSegments)):
                # check if the  the payload in i is not empty
                if listIncomingSegments[i] != "":
                    # check if checksum is correct
                    if listIncomingSegments[i].checkChecksum() != False:
                        payloadAndSeqnum.append([listIncomingSegments[i].seqnum, listIncomingSegments[i].payload])

            # create a unique list that dedupes and within the window range
            uniqueList = set([tuple(x) for x in payloadAndSeqnum])
            uniqueList = [list(x) for x in set([tuple(x) for x in uniqueList])]
            uniqueList = [item for item in uniqueList if item[0] >= self.currSegWindow[0] and item[0] <= self.currSegWindow[1]]

            # if the currentACK (frontWindow plus len of list) is the expected ACK then do the following
            if (self.currSegWindow[0] + len(uniqueList)) == self.expectedAck:
                self.windowStart += 4
                self.windowEnd += 4
                segmentAck.setAck((self.currSegWindow[0] + len(uniqueList)))
                self.sendChannel.send(segmentAck)
                self.currAck += 4

            # process uniqueList into the serverDataList if the current index is not in the list
            for i in range(0, len(uniqueList)):
                if uniqueList[i] not in self.serverDataList:
                    self.serverDataList.append(uniqueList[i])

        return