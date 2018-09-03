from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IInterceptedProxyMessage
from burp import IMessageEditorController
from burp import IContextMenuInvocation
from java.net import URL
from java.awt import Dimension, Component, GridLayout, GridBagLayout, BorderLayout, FlowLayout
from javax import swing
from javax.swing.table import AbstractTableModel, DefaultTableModel
from javax.swing import JMenuItem, JTable, JScrollPane, JCheckBox
from StringIO import StringIO
import re
import threading
import random
from java.lang import Runnable
from java.util import ArrayList


class PyRunnable(Runnable):
    """This class is used to wrap a python callable object into a Java Runnable that is 
       suitable to be passed to various Java methods that perform callbacks.
    """
    def __init__(self, target, *args, **kwargs):
        """Creates a PyRunnable.
           target - The callable object that will be called when this is run.
           *args - Variable positional arguments
           **wkargs - Variable keywoard arguments.
        """
        self.target = target
        self.args = args
        self.kwargs = kwargs
    
    
    def run(self):
        self.target(*self.args, **self.kwargs)


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuInvocation):
    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        self._callbacks.setExtensionName("Blind XSS")
        # lists of hosts with querys

        self._dictPayloads = {}
        self._dictPayloads_headers = {}
        self._dictPayloads_params = {}
        self._dictHeaders = {}
        self._dictParams = {}

        self.status_flag = False
        self.table_flag = 0
        self.start_button_text = 'Start process'
        self.stop_button_text = 'Stop process'

        # build UI
        self._tableModelPayloads = DefaultTableModel() 
        self._tableModelPayloads.addColumn("Payload")
        self._tableModelPayloads.addColumn("Using")

        self._tableModelHeaders = DefaultTableModel() 
        self._tableModelHeaders.addColumn("Header")
        self._tableModelHeaders.addColumn("Value")

        self._tableModelParams = DefaultTableModel() 
        self._tableModelParams.addColumn("Parameter")
        self._tableModelParams.addColumn("Value")

        boxVertical = swing.Box.createVerticalBox()

        boxHorizontal = swing.Box.createHorizontalBox()
        label = swing.JLabel("Data")
        boxHorizontal.add(swing.JLabel("Data"))
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self._table = JTable(self._tableModelPayloads)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMaximumSize(Dimension(400,400))
        boxHorizontal.add(self._scrolltable)

        self._table = JTable(self._tableModelHeaders)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMaximumSize(Dimension(400,400))
        boxHorizontal.add(self._scrolltable)

        self._table = JTable(self._tableModelParams)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMaximumSize(Dimension(400,400))
        boxHorizontal.add(self._scrolltable)

        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Enter Payload/Header/Parameter: (For payload use $HEADER$/$PARAM$)"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._paramField = swing.JTextField('')
        self._paramField.setMaximumSize(Dimension(500, 30))
        boxHorizontal.add(self._paramField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Enter Value (Example: burpcollaborator.net)"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._valueField = swing.JTextField('')
        self._valueField.setMaximumSize(Dimension(500, 30))
        boxHorizontal.add(self._valueField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self._checkBoxPayload = JCheckBox('Payload', True, actionPerformed = self.onCheck)
        boxHorizontal.add(self._checkBoxPayload)
        self._checkBoxHeader = JCheckBox('Header', actionPerformed = self.onCheck)
        boxHorizontal.add(self._checkBoxHeader)
        self._checkBoxParam = JCheckBox('Param', actionPerformed = self.onCheck)
        boxHorizontal.add(self._checkBoxParam)
        boxVertical.add(boxHorizontal)


        boxHorizontal = swing.Box.createHorizontalBox()
        submitQueryButton = swing.JButton('Create Row',actionPerformed=self.runQuery)
        boxHorizontal.add(submitQueryButton)

        clearQueryButton = swing.JButton('Delete Row',actionPerformed=self.clearQueue)
        boxHorizontal.add(clearQueryButton)
        boxVertical.add(boxHorizontal)


        boxHorizontal = swing.Box.createHorizontalBox()
        addPayloadButton = swing.JButton('Update Tables', actionPerformed=self.updateTables)
        boxHorizontal.add(addPayloadButton)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Output"))
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self._resultsTextArea = swing.JTextArea()
        resultsOutput = swing.JScrollPane(self._resultsTextArea)
        resultsOutput.setMaximumSize(Dimension(800,200))
        boxHorizontal.add(resultsOutput)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        submitSearchButton = swing.JButton(self.start_button_text, actionPerformed=self.active_flag)
        boxHorizontal.add(submitSearchButton)
        clearSearchButton = swing.JButton(self.stop_button_text, actionPerformed=self.active_flag)
        boxHorizontal.add(clearSearchButton)
        clearSearchButton = swing.JButton('Clear Search Output',actionPerformed=self.clearOutput)
        boxHorizontal.add(clearSearchButton)
        boxVertical.add(boxHorizontal)

        self._jScrollPanel = JScrollPane(boxVertical)
        self._jScrollPanel.setMaximumSize(Dimension(1000,2000))
        self._jScrollPanel.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)


        # add the custom tab to Burp's UI
        self._callbacks.customizeUiComponent(self._jScrollPanel)

        self._callbacks.addSuiteTab(self)
        # register ourselves as an HTTP listener
        self._callbacks.registerHttpListener(self)

        return


    def onCheck(self, event):
        if self._checkBoxPayload.isSelected() and self.table_flag != 0:
            self.table_flag = 0
            self._checkBoxHeader.setSelected(False)
            self._checkBoxParam.setSelected(False)


        if self._checkBoxHeader.isSelected() and self.table_flag != 1:
            self.table_flag = 1
            self._checkBoxParam.setSelected(False)
            self._checkBoxPayload.setSelected(False)


        if self._checkBoxParam.isSelected() and self.table_flag != 2:
            self.table_flag = 2
            self._checkBoxHeader.setSelected(False)
            self._checkBoxPayload.setSelected(False)


    # run Query for Add to Queue Button
    def runQuery(self, button):
        table_number = self.table_flag
        par = []
        val = []
        if self._paramField.text == "" or self._valueField.text == "":
            return
        else:
            paramString = self._paramField.text
            for word in paramString.split(','):
                word = word.strip() #delete spaces
                word = word.lstrip() #delete spaces
                if word != "":
                    par.append(word)
            valueString = self._valueField.text
            for word in valueString.split(','):
                word = word.strip() #delete spaces
                word = word.lstrip() #delete spaces
                if word != "":
                    val.append(word)

        if table_number == 0:
            self._dictPayloads.update(dict(zip(par, ['1'] * len(par))))
            for idx, key in enumerate(dict(zip(par, ['1'] * len(par)))):
                self._tableModelPayloads.insertRow(self._tableModelPayloads.getRowCount(), [key, '1'])
        elif table_number == 1:
            self._dictHeaders.update(dict(zip(par, val)))
            for idx, key in enumerate(dict(zip(par, val))):
                self._tableModelHeaders.insertRow(self._tableModelHeaders.getRowCount(), [key, self._dictHeaders[key]])
        elif table_number == 2:
            self._dictParams.update(dict(zip(par, val)))
            for idx, key in enumerate(dict(zip(par, val))):
                self._tableModelParams.insertRow(self._tableModelParams.getRowCount(), [key, self._dictParams[key]])
        self._paramField.setText("")
        self._valueField.setText("")


    # Clear Queue Function
    def clearQueue(self, button):
        table_number = self.table_flag

        if table_number == 0:
            data = self._tableModelPayloads.getDataVector()
            try:
                self._dictPayloads.pop(data[-1][0])
            except Exception:
                pass
            self._tableModelPayloads.removeRow(self._tableModelPayloads.getRowCount()-1)
        elif table_number == 1:
            data = self._tableModelHeaders.getDataVector()
            try:
                self._dictHeaders.pop(data[-1][0])
            except Exception:
                pass
            self._tableModelHeaders.removeRow(self._tableModelHeaders.getRowCount()-1)
        elif table_number == 2:
            data = self._tableModelParams.getDataVector()
            try:
                self._dictParams.pop(data[-1][0])
            except Exception:
                pass
            self._tableModelParams.removeRow(self._tableModelParams.getRowCount()-1)


    def updateTables(self, button):
        self._dictPayloads = {x[0]:x[1] for x in self._tableModelPayloads.getDataVector()}
        self._dictHeaders = {x[0]:x[1] for x in self._tableModelHeaders.getDataVector()}
        self._dictParams = {x[0]:x[1] for x in self._tableModelParams.getDataVector()}


    # Clear GUI Output Function
    def clearOutput(self, button):
        self._resultsTextArea.setText("")


    def active_flag(self, button):
        if self.start_button_text == button.getSource().text and not self.status_flag:
            for idx, key in enumerate(self._dictPayloads):
                if "$HEADER$" in key and not self._dictPayloads_headers.get(key) and self._dictPayloads[key] == '1':
                    self._dictPayloads_headers[key] = self._dictPayloads[key]

            for idx, key in enumerate(self._dictPayloads):
                if "$PARAM$" in key and not self._dictPayloads_params.get(key) and self._dictPayloads[key] == '1':
                    self._dictPayloads_params[key] = self._dictPayloads[key]

            self.status_flag = True
            self.appendToResults("Proxy start...\n")

        elif self.stop_button_text == button.getSource().text and self.status_flag:
            self.status_flag = False
            self.appendToResults("Proxy stop...\n")


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.status_flag:
            return
        # only process requests
        if not messageIsRequest:
            return

        requestString = messageInfo.getRequest().tostring()

        listHeader = re.findall('([\w-]+):\s?(.*)', requestString)
        dictRealHeaders = {x[0].lower():x[1] for x in listHeader}

        for index, key in enumerate(self._dictHeaders):
            if key.lower() in dictRealHeaders.keys():
                if len(self._dictPayloads_headers.keys()) == 0:
                    requestString = requestString.replace(dictRealHeaders.get(key.lower()), self._dictHeaders.get(key), 1)
                else:
                    payload = random.choice(self._dictPayloads_headers.keys())
                    payload = payload.replace("$HEADER$", self._dictHeaders.get(key), 1)
                    requestString = requestString.replace(dictRealHeaders.get(key.lower()), payload, 1)
            else:
                pass

        listParam = re.findall('[\?|\&]([^=]+)\=([^& ])+', requestString)
        dictRealParams = {x[0].lower():x[1] for x in listParam}
        url = requestString.split(" HTTP/1.")
        for index, key in enumerate(self._dictParams):
            if key.lower() in dictRealParams.keys():
                if len(self._dictPayloads_params.keys()) == 0:
                    url[0] = url[0].replace(dictRealParams.get(key.lower()), self._dictParams.get(key), 1)
                else:
                    payload = random.choice(self._dictPayloads_params.keys())
                    payload = payload.replace("$PARAM$", self._dictParams.get(key), 1)
                    url[0] = url[0].replace(dictRealParams.get(key.lower()), payload, 1)
            else:
                pass
        requestString = "{} HTTP/1.{}".format(url[0], url[1])

        self.appendToResults(requestString.encode())
        messageInfo.setRequest(requestString.encode())

        
    # Fnction to provide output to GUI
    def appendToResults(self, s):
        """Appends results to the resultsTextArea in a thread safe mannor. Results will be
           appended in the order that this function is called.
        """
        def appendToResults_run(s):  
            self._resultsTextArea.append(s)

        swing.SwingUtilities.invokeLater(PyRunnable(appendToResults_run, s))


    def getTabCaption(self):
        return "Blind XSS"


    def getUiComponent(self):
        return self._jScrollPanel
