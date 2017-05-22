import json, getopt, sys, traceback


def usage():
    print "-e COWXXXXX      Event Id's to List"
    print "-l               Files to List that were uploaded"
    print "-f cowrie.json   log file to read "
    print "-s sessionid     Session ID to match"
    print "-k key:value     Search for key:value in json object"


def main():
    file = "cowrie.json"
    listfiles = False
    search_terms = {}
    try:
        opts, args = getopt.getopt(sys.argv[1:], "e:s:luf:k:", ["help"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    output = None
    verbose = False
    for o, a in opts:
        if o == "-v":
            verbose = True
        elif o == "-e":
            search_terms["eventid"] = a
        elif o == "-s":
            search_terms["session"] = a
        elif o == "-f":
            file = a
        elif o == "-k":
            key_value = a
            (key, value) = a.split(":")
            search_terms[key] = value
        elif o == "-l":
            search_terms["eventid"] = "COW0007"
            listfiles = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()

        else:
            assert False, "unhandled option"
            # ...

    event_objects = read_cowrie_file(file, search_terms)
    for event in event_objects:
        if listfiles:
            print "File:" + event['url'] + "\n OutputFile:" + event['outfile']
        else:
            print json.dumps(event, indent=5)


def read_cowrie_file(file, searchterms):
    event_objects = [];
    try:
        has_all_flags = True
        with open(file) as f:
            for line in f:
                event_object = json.loads(line)
                for key in searchterms:
                    if searchterms[key] == event_object[key]:   
                        pass
                    else:
                        has_all_flags = False
                if has_all_flags:
                    event_objects.append(event_object)
                has_all_flags = True

    except Exception as err:
        print err
        traceback.print_exc()

    return event_objects


if __name__ == "__main__":
    main()
