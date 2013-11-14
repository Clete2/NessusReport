class NessusParser:
    def loadXML(self, filename):
        self.xml = ElementTree.parse(filename)
        self.rootElement = self.xml.getroot()
    
    def getHosts(self):
        return self.rootElement.findall("./Report/ReportHost")
    
    def getHostProperties(self, host):
        properties = {}        
    
        hostProperties = host.findall("./HostProperties")[0]
        hostnames = hostProperties.findall("./tag[@name='host-fqdn']")
        if(len(hostnames) >= 1):
            properties['host-fqdn'] = hostnames[0].text
        properties['host-ip'] = hostProperties.findall("./tag[@name='host-ip']")[0].text
        properties['HOST_START'] = hostProperties.findall("./tag[@name='HOST_START']")[0].text
        properties['HOST_END'] = hostProperties.findall("./tag[@name='HOST_END']")[0].text

        return properties
        
    def getReportItems(self, host):
        return host.findall("./ReportItem")
        
    def getReportItemProperties(self, reportItem):
        properties = reportItem.attrib

        if(properties.has_key('severity')):
            del(properties['severity'])
            
        if(properties.has_key('pluginFamily')):
            del(properties['pluginFamily'])
        
        return properties
        
    def getReportItemDetails(self, reportItem):
        details = {}
        
        details['description'] = reportItem.findall("./description")[0].text
        
        solutionElements = reportItem.findall("./solution")
        if(len(solutionElements) >= 1):
            details['solution'] = solutionElements[0].text
        
        pluginOutputElements = reportItem.findall("./plugin_output")
        if(len(pluginOutputElements) >= 1):
            details['plugin_output'] = pluginOutputElements[0].text
            
        return details
        
import xml.etree.ElementTree as ElementTree
import csv
import glob
import re

def transformIfAvailable(inputDict, inputKey, outputDict, outputKey):
    if(inputDict.has_key(inputKey)):
        inputDict[inputKey] = inputDict[inputKey].replace("\n"," ")
        #if(inputDict[inputKey].startswith("\n")):
        #    inputDict[inputKey] = inputDict[inputKey][1:]
        
        # Excel has a hard limit of 32,767 characters per cell.
        # Let's make it an even 32K.
        if(len(inputDict[inputKey]) > 32000):
            inputDict[inputKey] = inputDict[inputKey][:32000] +" [Text Cut Due To Length]"
            
        outputDict[outputKey] = inputDict[inputKey]
            
header = ['IP','Hostname','Port','Service Name','Protocol','Plugin ID','Plugin Name','Plugin Description','Solution','Plugin Output','Host Start Time','Host End Time']

outFile = open("Scan_Results.csv", "wb")
csvWriter = csv.DictWriter(outFile, header, quoting=csv.QUOTE_ALL)
csvWriter.writeheader()

nessusParser = NessusParser()

for fileName in glob.glob("*.nessus"):
    nessusParser.loadXML(fileName)

    hosts = nessusParser.getHosts()

    hostReports = []

    for host in hosts:
        # Get properties for this host
        hostProperties = nessusParser.getHostProperties(host)
        
        # Get all findings for this host
        reportItems = nessusParser.getReportItems(host)
            
        for reportItem in reportItems:
            reportItemDict = {}
        
            # Get the metadata and details for this report item
            reportItemProperties = nessusParser.getReportItemProperties(reportItem)
            reportItemDetails = nessusParser.getReportItemDetails(reportItem)
        
            # Create dictionary for line
            transformIfAvailable(hostProperties, "host-ip", reportItemDict, header[0])
            transformIfAvailable(hostProperties, "host-fqdn", reportItemDict, header[1])
            transformIfAvailable(reportItemProperties, "port", reportItemDict, header[2])
            transformIfAvailable(reportItemProperties, "svc_name", reportItemDict, header[3])
            transformIfAvailable(reportItemProperties, "protocol", reportItemDict, header[4])
            transformIfAvailable(reportItemProperties, "pluginID", reportItemDict, header[5])
            transformIfAvailable(reportItemProperties, "pluginName", reportItemDict, header[6])
            transformIfAvailable(reportItemDetails, "description", reportItemDict, header[7])
            transformIfAvailable(reportItemDetails, "solution", reportItemDict, header[8])
            transformIfAvailable(reportItemDetails, "plugin_output", reportItemDict, header[9])
            transformIfAvailable(hostProperties, "HOST_START", reportItemDict, header[10])
            transformIfAvailable(hostProperties, "HOST_END", reportItemDict, header[11])
            
            hostReports.append(reportItemDict)

    csvWriter.writerows(hostReports)
        
outFile.close()