#!/usr/bin/python

'''
Example file on how to get the exported IDS data from MISP
Add your API key, set the MISP host and define the output file.
'''

import urllib2, xml.etree.ElementTree as ET, hashlib, logging, os

MISP_HOST="http://misp.example/"    #Your MISP url/IP.
API_KEY="1234"    #Your MISP API key.
EXPORT_DATA="events/xml/download/"    #The MISP API query.
EXPORT_FILE="tmp/misp-export.xml"    #What to call the XML export file.

MISP_HASH="tmp/misp-export.md5"    #What to call the XML export md5 file.
HASH_FUNCTION = hashlib.sha256()    #Set which hash function to use, default SHA256.

BRO_FILENAME="tmp/intel.dat"    #Name of the output file formatted for BRO.
BRO_SENSORS="sensors.txt"    #File containing a list of IPs/Domains for your BRO sensors.
BRO_PATH="/opt/bro/share/bro/intel/"    #Path on the remote BRO sensor where the intel file is stored.

#Fire up the logger.
try:
    logging.basicConfig(filename="tmp/misp2bro.log", level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("misp2bro")
except:
    logger.error("Could not start logger.")

#Before anything, make sure theres a tmp folder.
try:
    os.makedirs("tmp")
    logger.info("Created tmp folder.")
except OSError:
    if not os.path.isdir("tmp"):
        raise

def getMispExport():
    """
    This function calls on the MISP API to receive an export file of all events.
    The return is a boolian value
    """

    #Set up the HTTP request and URL.
    URL= "%s/%s" %(MISP_HOST, EXPORT_DATA)

    try:
        request = urllib2.Request(URL)
    except:
        logger.error("Could not set urllib request.")
        return False

    #Get the MISP export file and write it to file.
    with open(EXPORT_FILE, 'w') as f:
        request.add_header('Authorization', API_KEY)
        try:
            data = urllib2.urlopen(request).read()
        except:
            logger.error("Could not complete HTTP request to MISP server.")
            return False
        f.write(data)

    f.closed

    logger.info("Successfully downloaded the MISP export file.")

    #Run the new file through a hash check to see if its new.
    return checkHash(EXPORT_FILE, MISP_HASH)


def checkHash(exportfile, hashfile):
    """
    This function evaluates if the MISP export file is different from the last
    export file retrieved, using a hash comparison.
    Returns a boolian value
    """

    #Check if the old hash file is stored.
    if os.path.isfile(hashfile):

        #First line in the file is the old hash value.
        with open(hashfile, 'r') as hf:
            oldhash = hf.readline()
        hf.closed

        #Generate a hash value for the newly retrieved file.
        newhash = hashFile(exportfile, HASH_FUNCTION)

        #Compare the hash values
        if newhash == oldhash:
            logger.info("Downloaded MISP export file was the same as last.")
            return False    #Same file.
        else:
            #Write the new file hash into the old file.
            with open(hashfile, 'w') as hf:
                hf.write(newhash)
            hf.closed
            logger.info("Downloaded MISP export file was new, parsing now.")
            return True    #New file.

    #Old has file doesnt exist, first run of program, create it.
    else:
        #Write the new file hash into the old file
        with open(hashfile, 'w') as hf:
            hf.write(hashFile(exportfile, HASH_FUNCTION))
        hf.closed
        logger.info("Downloaded MISP export file was new, parsing now.")
        return True    #New file.


def hashFile(filename, hasher, blocksize=65536):
    """
    This function creates a hash value of the contents of a file.
    The return value is a string.
    """

    #Read the file in chunks and update the hash funcion.
    with open(filename, "r+b") as f:
        for block in iter(lambda: f.read(blocksize), ""):
            hasher.update(block)
    f.closed

    #Return the hash value.
    return hasher.hexdigest()

def parseXML(file):
    """
    This function takes an XML file and parses it.
    The return value is the XML root object.
    """

    try:
        tree = ET.parse(file)
    except:
        logger.error("Could not parse XML file.")

    logger.info("MISP XML successfully parsed.")
    #Return the xml tree root.
    return tree.getroot()

def makeBroFiles(root):
    """
    This function takes the XML tree from MISP, finds the relevant elements and writes them to the BRO files.
    The return is a boolean value for success.
    """

    events = root.findall('Event')

    #Check that there are events in the response. If not, we're done.
    if not len(events):
        logger.info("MISP export file did not contain any events.")
        return False

    else:
        logger.info("MISP export file contains events, processing now.")

        counter = 0
        #Start the file.
        #TODO: When MISP has support for threat hierarchy, spread the IOC into multiple files.
        with open(BRO_FILENAME, "w") as f:

            #Write the header field labels.
            f.write("#fields indicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\tmeta.if_in\n")

            #For all the events with attributes that are to be pushed to IDS, write a line in the BRO file.
            for event in events:

                #We only want the events with attributes.
                if int(event.find('attribute_count').text):

                    for attribute in event.findall('Attribute'):

                        #We only want the attributes that are for IDS
                        if int(attribute.find('to_ids').text):

                            writeBroLine(f, attribute.find('type').text, event.find('info').text, attribute.find('category').text, attribute.find('value').text, event.find('id').text)
                            counter=counter+1
                            logger.info("Added attribute for event"+event.find('id').text)
        f.closed

        #We only want to continue if we actually wrote any attributes to a file.
        if counter:
            logger.info("Successfully created a BRO file.")
            #Make life easier for BRO and sort/unique the IOC.
            try:
                os.system("(head -n 1 "+BRO_FILENAME+" && tail -n +2 "+BRO_FILENAME+" |sort -uk 1) > "+BRO_FILENAME+"2 && mv "+BRO_FILENAME+"2 "+BRO_FILENAME)
                logger.info("Sorted and removed duplicates from BRO file.")
            except:
                logger.error("Could not sort and unique the BRO file.")
                return False
            return True
        else:
            logger.info("There were no attributes to export to BRO, exiting.")
            return False



def writeBroLine(f, atype, info, category, value, eid):
    """
    This function writes lines to the BRO files dependant on the IOC type.
    It returns a boolean value for success.
    """

    #Write line to file if IP-address.
    if atype == "ip-src" or atype == "ip-dst":
        f.write(value+"\tIntel::ADDR\t"+category+" - "+info+"\t"+MISP_HOST+"events/view/"+eid+"\tT\t-\n")
        return True

    #Write line to file if Domain.
    elif atype == "domain":
        f.write(value+"\tIntel::DOMAIN\t"+category+" - "+info+"\t"+MISP_HOST+"events/view/"+eid+"\tT\t-\n")
        return True

    #Write line to file if URL.
    elif atype == "url":

        #We dont want to trigger on external analysis links.
        if not category == "External analysis":

            #BRO doesnt want the protocol marker.
            if value.startswith("https://"):
                value = value[8:]
            elif value.startswith("http://"):
                value = value[7:]
            f.write(value+"\tIntel::URL\t"+category+" - "+info+"\t"+MISP_HOST+"events/view/"+eid+"\tT\t-\n")
        return True

    #Write line to file if Email Address.
    elif atype == "email-src" or atype == "email-dst" or atype == "target-email":
        f.write(value+"\tIntel::EMAIL\t"+category+" - "+info+"\t"+MISP_HOST+"events/view/"+eid+"\tT\t-\n")
        return True

    #Write line to file if MD5 hash sum.
    elif atype == "md5":
        f.write(value+"\tIntel::FILE_HASH\t"+category+" - "+info+"\t"+MISP_HOST+"events/view/"+eid+"\tT\t-\n")
        return True

    #Write line to file if Filename.
    elif atype == "filename":
        f.write(value+"\tIntel::FILE_NAME\t"+category+" - "+info+"\t"+MISP_HOST+"events/view/"+eid+"\tT\t-\n")
        return True

    #Special case for MISP double value syntax, split it into two indicators.
    elif atype == "filename|md5":
        value = value.split('|')
        f.write(value[1]+"\tIntel::FILE_HASH\t"+category+" - "+info+"\t"+MISP_HOST+"events/view/"+eid+"\tT\t-\n")
        f.write(value[0]+"\tIntel::FILE_NAME\t"+category+" - "+info+"\t"+MISP_HOST+"events/view/"+eid+"\tT\t-\n")
        return True

    #IOC type isnt something BRO can deal with, return False.
    else:
        return False

def syncToSensor():
    """
    This function syncs the BRO IOC list with the BRO sensors, then restarts the BRO processes on the sensors.
    The function returns a boolean value for success.
    """

    #Open the file containing the sensor IPs/domains.
    with open(BRO_SENSORS, 'r') as f:

        #Loop over all the sensors.
        for sensor in f:

            #Use rsync to transfer the IOC file to the BRO sensor.
            try:
                os.system("rsync -avz -e ssh "+BRO_FILENAME+" root@"+sensor.strip()+":"+BRO_PATH)
                logger.info("Successfully synced with sensor "+sensor.strip())
            except:
                logger.error("Could not sync file to sensor "+sensor.strip())
                return False

            #BRO needs to be reloaded and restarted in order to use the new file
            #TODO: Look into appending the file, as BRO apparently can read new lines without restarting.
            try:
                os.system("ssh root@"+sensor.strip()+" \'nsm_sensor_ps-restart --only-bro\'")
                logger.info("Successfully restarted BRO on sensor "+sensor.strip())
            except:
                logger.error("Could not restart BRO on "+sensor.strip())
                return False

    f.closed
    return True


"""Start of the main program"""
if getMispExport(): #TODO: Take an argument for forcing sync even if MISP isnt new.
    if makeBroFiles(parseXML(EXPORT_FILE)):
        if syncToSensor():
            logger.info("Successfully exported MISP to BRO.")

