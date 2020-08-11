import logging

def writeFile(fileName, header, data):
    logger = logging.getLogger(__name__)

    output_file = open(fileName, 'w')
    logger.info('Outputting results to [%s]', fileName)
    output_file.write(header + '\n')
    for element in data:
        output_file.write(element + '\n')
    output_file.close()
