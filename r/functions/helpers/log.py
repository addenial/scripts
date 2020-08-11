import logging

def configureLogger(args):
    # Logger
    # Level      Severity Value
    # Critical   50
    # Error      40
    # Warning    30
    # Info       20
    # DEBUG      10
    # NOTSET     0
    # Messages which are less severe than lvl will be ignored
    if args.verbose is True:
        logLevel = 10
    elif args.silent is True:
        logLevel = 40
    else:
        logLevel = 20

    try:
        if args.verbose is True:
            logging.basicConfig(filename='log.txt', format='%(asctime)-19s %(levelname)-8s %(name)-36s %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S', level=logLevel)
        else:
            logging.basicConfig(filename='log.txt', format='%(asctime)-19s %(levelname)-8s %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S', level=logLevel)
    except:
        print 'Could Not Configure Log File'
        exit()