# from ActionHook import *
# access = checkWPDataAccessHook()
# print(access)
# for i in access:
#     print(getWPExportedData(i))
# print(checkWPDataDeletionHook())
# print(getInvokedFnID(24521,[]))

# print(getInvokedFnID(24798,[]))

# from DataFlowTracking import hasDataflowPath
# print(hasDataflowPath(7343,17544))

# from PathAnalyzerHelper import *
# print(getThirdPartyDataTypeFromPolicy())
# from Preproccess import remove_edge_from_key_to_sink
# from Detectors.Runtime import SECURITY_DETECTOR_MANAGER
# SECURITY_DETECTOR_MANAGER.run()
# remove_edge_from_key_to_sink()

from Preproccess import wp_localize_script_to_js
wp_localize_script_to_js()