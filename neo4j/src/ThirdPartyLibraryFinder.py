from NeoHelper import *
from Utls import *


# TODO: run the tool on the third party libraries to collect the info on their sharing protocol
def getLibrarySharingProtocol():

    libSharedInfo = {
        "commonfunctions.php": ["email"],
        "class-billmate-cardpay.php": ["name", "address", "credit card"],
    }

    return libSharedInfo


def findLibrary(plugin_dir):

    # from composer
    paths, total_files = getAllFilepathsWithEXT(plugin_dir, "composer.lock")
    libraries = []
    for path in paths:
        print(path)
        dependenciesListJSON = read_json(path)
        for package in dependenciesListJSON["packages"]:
            libraries.append(package["name"])

    # print([os.path.abspath(name)    for name in os.listdir(plugin_dir+"/library") if os.path.isdir(name)])

    # print([name for name in os.listdir(plugin_dir) if os.path.isdir(name)])

    # adding all the files from library folder
    for root, dirs, files in os.walk(plugin_dir, topdown=False):
        for name in dirs:
            paths.append(os.path.join(root, name))
            if "library" in name:
                libraries.append(files)

    return libraries


def checkSharingConfirmation(graph, libraryName, piiList):

    foundPIIConfirmationList = []
    for keyword in piiList:
        if keyword not in foundPIIConfirmationList:
            query = f"""match(n) where n.type contains "AST_HTML_TEXT" and n.code contains '{keyword}' return n;"""
            results = graph.run(cypher=query).data()

            for res in results:
                msg = res["n"]["code"]
                if libraryName in msg:
                    foundPIIConfirmationList.append(keyword)

    if len(foundPIIConfirmationList) == len(piiList):
        return True
    return False


def run():
    graph = getGraph()

    plugin_dir = (
        "/home/faysal/code/jhu/gdpr/GDPR-CCPA-violation-checker/navex_docker/exampleApps/gdprplugin"
    )
    plugin_dir = "/home/faysal/code/jhu/gdpr/GDPR-CCPA-violation-checker/navex_docker/exampleApps/billmate-payment-gateway-for-woocommerce/code/billmate-payment-gateway-for-woocommerce/"
    libraries = findLibrary(plugin_dir)
    for library in libraries:
        print(library)

    sharedProtocol = getLibrarySharingProtocol()
    for libraryName, piiList in sharedProtocol.items():
        flag = checkSharingConfirmation(graph, libraryName, piiList)
        if flag == False:
            print("Violates Sharing Policy!")
            return
    print("Comply with Sharing Policy!")


if __name__ == "__main__":
    run()
