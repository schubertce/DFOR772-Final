import json
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.datamodel import Score
from java.util import Arrays
from java.io import BufferedReader, InputStreamReader
from java.util import ArrayList
from datetime import datetime

#Convert date/time from JSON logs to readable format
def iso_datetime_to_epoch(iso_datetime_str):
    # Parse the ISO 8601 string to a datetime object
    dt = datetime.strptime(iso_datetime_str, '%Y-%m-%dT%H:%M:%SZ')

    # Calculate the total seconds from epoch start
    # Manually creating a UTC datetime for epoch start
    epoch_start = datetime(1970, 1, 1)
    epoch_seconds = int((dt - epoch_start).total_seconds())

    return epoch_seconds

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class AWSCloudTrailLogParserIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "AWS CloudTrail Log Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module parses AWS CloudTrail logs."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return AWSCloudTrailLogParserIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class AWSCloudTrailLogParserIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(AWSCloudTrailLogParserIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        self.context = context


    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()

        # For our example, we will use FileManager to get all
        # files with the word "test"
        # in the name and then count and read them
        # FileManager API: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1casemodule_1_1services_1_1_file_manager.html
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles("%CloudTrail%")

        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0

        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Create/Get artifact to use
            artId = blackboard.getOrAddArtifactType("TSK_CLOUDTRAIL_LOG_ENTRIES", "CloudTrail Log Entries")

            # Create/Get attributes to use
            attId = blackboard.getOrAddAttributeType("TSK_NAME",
                                                     BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                     "Event")
            attId1 = blackboard.getOrAddAttributeType("TSK_TYPE",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "Event Type")
            attId2 = blackboard.getOrAddAttributeType("TSK_DATETIME",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                                                      "Date\\Time")
            attId3 = blackboard.getOrAddAttributeType("TSK_IP_ADDRESS",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "Source IP Address")
            attId4 = blackboard.getOrAddAttributeType("TSK_REGION",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "AWS Region")
            attId5 = blackboard.getOrAddAttributeType("TSK_USERAGENT",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "User Agent")
            attId6 = blackboard.getOrAddAttributeType("TSK_USERNAME",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "User Name")
            attId7 = blackboard.getOrAddAttributeType("TSK_ARN",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "ARN")
            attId8 = blackboard.getOrAddAttributeType("TSK_ACCOUNT_ID",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "Account ID")
            attId9 = blackboard.getOrAddAttributeType("TSK_PARAMETERS",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "Request Parameters")
            attId10 = blackboard.getOrAddAttributeType("TSK_ADDITIONAL_DATA",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "Additional Event Data")

            inputStream = ReadContentInputStream(file)
            reader = BufferedReader(InputStreamReader(inputStream, "UTF-8"))
            log_content = []
            line = reader.readLine()
            while line:
                log_content.append(line)
                line = reader.readLine()

            log_content_str = ''.join(log_content)
            try:
                log_data = json.loads(log_content_str)
                for event in log_data["Records"]:
                    eventName = event.get("eventName")
                    eventType = event.get("eventType")
                    dateTime = event.get("eventTime", "1970-01-01T00:00:00Z")  # default to epoch start if missing
                    dateTimeMillis = iso_datetime_to_epoch(dateTime)
                    sourceIP = event.get("sourceIPAddress")
                    awsRegion = event.get("awsRegion")
                    userAgent = event.get("userAgent")
                    userName = event.get("userIdentity", {}).get("userName")
                    arn = event.get("userIdentity", {}).get("arn")
                    accountID = event.get("userIdentity", {}).get("accountId")
                    reqParam = event.get("requestParameters")
                    addEventData = event.get("additionalEventData")

                    artifact = file.newArtifact(artId.getTypeID())

                    attributes = ArrayList()

                    attributes.add(
                        BlackboardAttribute(attId, AWSCloudTrailLogParserIngestModuleFactory.moduleName, eventName))
                    attributes.add(
                        BlackboardAttribute(attId1, AWSCloudTrailLogParserIngestModuleFactory.moduleName, eventType))
                    attributes.add(
                        BlackboardAttribute(attId2, AWSCloudTrailLogParserIngestModuleFactory.moduleName, dateTimeMillis))
                    attributes.add(
                        BlackboardAttribute(attId3, AWSCloudTrailLogParserIngestModuleFactory.moduleName, sourceIP))
                    attributes.add(
                        BlackboardAttribute(attId4, AWSCloudTrailLogParserIngestModuleFactory.moduleName, awsRegion))
                    attributes.add(
                        BlackboardAttribute(attId5, AWSCloudTrailLogParserIngestModuleFactory.moduleName, userAgent))
                    attributes.add(
                        BlackboardAttribute(attId6, AWSCloudTrailLogParserIngestModuleFactory.moduleName, userName))
                    attributes.add(
                        BlackboardAttribute(attId7, AWSCloudTrailLogParserIngestModuleFactory.moduleName, arn))
                    attributes.add(
                        BlackboardAttribute(attId8, AWSCloudTrailLogParserIngestModuleFactory.moduleName, accountID))
                    attributes.add(
                        BlackboardAttribute(attId9, AWSCloudTrailLogParserIngestModuleFactory.moduleName, str(reqParam)))
                    attributes.add(
                        BlackboardAttribute(attId10, AWSCloudTrailLogParserIngestModuleFactory.moduleName, str(addEventData)))

                    try:
                        artifact.addAttributes(attributes)
                    except:
                        self.log(Level.INFO, "Error adding attribute to artifact")

                    # artifacts try catch
                    try:
                        blackboard.postArtifact(artifact)
                    except:
                        self.log(Level.INFO, "Error posting artifact")


                    # Update the progress bar
                    progressBar.progress(fileCount)


            except ValueError as e:  # Using ValueError to catch JSON decoding errors
                self.log(Level.SEVERE, "Could not parse JSON data from file: " + file.getName() + "; Error: " + str(e))

            reader.close()
            inputStream.close()

        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "AWS CloudTrail Log Parser", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK
