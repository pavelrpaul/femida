from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IInterceptedProxyMessage
from burp import IMessageEditorController
from burp import IContextMenuInvocation
from javax.swing import JLabel, JTextField, JOptionPane, JTabbedPane, JPanel, JButton, JMenuItem, JTable, JScrollPane, JCheckBox, BorderFactory, Box
from javax.swing.border import EmptyBorder
from java.awt import GridBagLayout, Dimension, GridBagConstraints, Color, FlowLayout, BorderLayout, Insets
from java.net import URL
# from java.awt import Dimension, Color, Component, GridLayout, GridBagLayout, BorderLayout, FlowLayout, GridBagConstraints
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
            # self.burp.appendToResults(str(self.burp._dictPayloads))
            self.burp._dictPayloads = {x[0]:x[1] for x in self.burp._tableModelPayloads.getDataVector()}
            # self.burp.appendToResults(str(self.burp._dictPayloads))
        elif self._type == 2:
            # self.burp.appendToResults(str(self.burp._dictHeaders))
            self.burp._dictHeaders = {x[0]:x[1] for x in self.burp._tableModelHeaders.getDataVector()}
            # self.burp.appendToResults(str(self.burp._dictHeaders))
        elif selfg._type == 3:
            # self.burp.appendToResults(str(self.burp._dictParams))
            self.burp._dictParams = {x[0]:x[1] for x in self.burp._tableModelParams.getDataVector()}
            # self.burp.appendToResults(str(self.burp._dictParams))
        # print(str(self.burp._dictPayloads))
#         self._tableModelHeaders.insertRow(self._tableModelHeaders.getRowCount(), ['1','1'])


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
    _jTextFieldTechniques = None
    _jLabelFuzzFactor = None
    _jTextFieldFuzzFactor = None
    _jLabelAdditionalCmdLine = None
    _jTextFieldAdditionalCmdLine = None
    _jButtonSetCommandLine = None
    _jLabelAbout = None

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

        self._jPanel.setBounds(0, 0, 1000, 1000)
        self._jLabelTechniques = JLabel("Your URL (my.burpcollaborator.net):")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 1
        self._jPanelConstraints.gridwidth = 2
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(0, 0, 10, 0)
        self._jPanel.add(self._jLabelTechniques, self._jPanelConstraints)

        self._jTextFieldTechniques = JTextField("", 30)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 2
        self._jPanelConstraints.gridy = 1
        self._jPanelConstraints.gridwidth = 4
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(0, 0, 10, 0)
        self._jPanel.add(self._jTextFieldTechniques, self._jPanelConstraints)

        self._jLabelTechniques = JLabel("Press to start:")
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.anchor = GridBagConstraints.WEST
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 0
        self._jPanelConstraints.gridwidth = 2
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(0, 0, 10, 0)
        self._jPanel.add(self._jLabelTechniques, self._jPanelConstraints)

        self.submitSearchButton = swing.JButton(self.start_button_text, actionPerformed=self.active_flag)
        self.submitSearchButton.setBackground(Color.WHITE)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 2
        self._jPanelConstraints.gridy = 0
        self._jPanelConstraints.gridwidth = 4
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(0, 0, 10, 0)
        self._jPanel.add(self.submitSearchButton, self._jPanelConstraints)


        self._tableModelPayloads = DefaultTableModel() 
        self._tableModelPayloads.addColumn("Payload")
        self._tableModelPayloads.addColumn("Using")

        self._tableModelHeaders = DefaultTableModel() 
        self._tableModelHeaders.addColumn("Header")
        self._tableModelHeaders.addColumn("Value")

        self._tableModelParams = DefaultTableModel() 
        self._tableModelParams.addColumn("Parameter")
        self._tableModelParams.addColumn("Value")


        self._table = JTable(self._tableModelPayloads)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._table.getModel().addTableModelListener(MyTableModelListener(self._table, self, 1))
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMinimumSize(Dimension(300, 200))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 2
        self._jPanelConstraints.gridwidth = 2
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(0, 0, 0, 10)
        self._jPanel.add(self._scrolltable, self._jPanelConstraints)

        self._table = JTable(self._tableModelHeaders)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._table.getModel().addTableModelListener(MyTableModelListener(self._table, self, 2))
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMinimumSize(Dimension(300, 200))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 2
        self._jPanelConstraints.gridy = 2
        self._jPanelConstraints.gridwidth = 2
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(0, 0, 0, 10)
        self._jPanel.add(self._scrolltable, self._jPanelConstraints)

        self._table = JTable(self._tableModelParams)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._table.getModel().addTableModelListener(MyTableModelListener(self._table, self, 3))
        self._scrolltable = JScrollPane(self._table)
        self._scrolltable.setMinimumSize(Dimension(300, 200))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 4
        self._jPanelConstraints.gridy = 2
        self._jPanelConstraints.gridwidth = 2
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(0, 0, 0, 0)
        self._jPanel.add(self._scrolltable, self._jPanelConstraints)


        addPayloadButton = swing.JButton('Add',actionPerformed=self.addToPayload)
        addPayloadButton.setBackground(Color.WHITE)
        addPayloadButton.setPreferredSize(Dimension(150, 40))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        # self._jPanelConstraints.anchor = GridBagConstraints.CENTER
        self._jPanelConstraints.gridx = 1
        self._jPanelConstraints.gridy = 3
        self._jPanelConstraints.gridwidth = 1
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(3, 0, 0, 10)
        self._jPanel.add(addPayloadButton, self._jPanelConstraints)

        deletePayloadButton = swing.JButton('Delete',actionPerformed=self.deleteToPayload)
        deletePayloadButton.setBackground(Color.WHITE)
        deletePayloadButton.setPreferredSize(Dimension(150, 40))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 3
        self._jPanelConstraints.gridwidth = 1
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(3, 0, 0, 0)
        self._jPanel.add(deletePayloadButton, self._jPanelConstraints)

        addHeaderButton = swing.JButton('Add',actionPerformed=self.addToHeader)
        addHeaderButton.setBackground(Color.WHITE)
        addHeaderButton.setPreferredSize(Dimension(150, 40))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        # self._jPanelConstraints.anchor = GridBagConstraints.CENTER
        self._jPanelConstraints.gridx = 3
        self._jPanelConstraints.gridy = 3
        self._jPanelConstraints.gridwidth = 1
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(3, 0, 0, 10)
        self._jPanel.add(addHeaderButton, self._jPanelConstraints)

        deleteHeaderButton = swing.JButton('Delete',actionPerformed=self.deleteToHeader)
        deleteHeaderButton.setBackground(Color.WHITE)
        deleteHeaderButton.setPreferredSize(Dimension(150, 40))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 2
        self._jPanelConstraints.gridy = 3
        self._jPanelConstraints.gridwidth = 1
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(3, 0, 0, 0)
        self._jPanel.add(deleteHeaderButton, self._jPanelConstraints)

        addParamsButton = swing.JButton('Add',actionPerformed=self.addToParams)
        addParamsButton.setBackground(Color.WHITE)
        addParamsButton.setPreferredSize(Dimension(150, 40))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        # self._jPanelConstraints.anchor = GridBagConstraints.CENTER
        self._jPanelConstraints.gridx = 5
        self._jPanelConstraints.gridy = 3
        self._jPanelConstraints.gridwidth = 1
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(3, 0, 0, 0)
        self._jPanel.add(addParamsButton, self._jPanelConstraints)

        deleteParamsButton = swing.JButton('Delete',actionPerformed=self.deleteToParams)
        deleteParamsButton.setBackground(Color.WHITE)
        deleteParamsButton.setPreferredSize(Dimension(150, 40))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 4
        self._jPanelConstraints.gridy = 3
        self._jPanelConstraints.gridwidth = 1
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(3, 0, 0, 0)
        self._jPanel.add(deleteParamsButton, self._jPanelConstraints)
        

        self._resultsTextArea = swing.JTextArea()
        resultsOutput = swing.JScrollPane(self._resultsTextArea)
        resultsOutput.setMinimumSize(Dimension(800,200))
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = 0
        self._jPanelConstraints.gridy = 4
        self._jPanelConstraints.gridwidth = 6
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(10, 0, 0, 0)
        self._jPanel.add(resultsOutput, self._jPanelConstraints)

        self.clearSearchButton = swing.JButton('Clear Search Output',actionPerformed=self.clearOutput)
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        # self._jPanelConstraints.anchor = GridBagConstraints.CENTER
        self._jPanelConstraints.gridx = 2
        self._jPanelConstraints.gridy = 5
        self._jPanelConstraints.gridwidth = 2
        self._jPanelConstraints.gridheight = 1
        self._jPanelConstraints.insets = Insets(3, 0, 0, 0)
        self._jPanel.add(self.clearSearchButton, self._jPanelConstraints)

        self._callbacks.customizeUiComponent(self._jPanel)

        self._callbacks.addSuiteTab(self)
        # register ourselves as an HTTP listener
        self._callbacks.registerHttpListener(self)

        return


    # def onCheck(self, event):
    #     if self._checkBoxPayload.isSelected() and self.table_flag != 0:
    #         self.table_flag = 0
    #         self._checkBoxHeader.setSelected(False)
    #         self._checkBoxParam.setSelected(False)


    #     if self._checkBoxHeader.isSelected() and self.table_flag != 1:
    #         self.table_flag = 1
    #         self._checkBoxParam.setSelected(False)
    #         self._checkBoxPayload.setSelected(False)


    #     if self._checkBoxParam.isSelected() and self.table_flag != 2:
    #         self.table_flag = 2
    #         self._checkBoxHeader.setSelected(False)
    #         self._checkBoxPayload.setSelected(False)


    # run Query for Add to Queue Button
    def addToPayload(self, button):
        self._tableModelPayloads.insertRow(self._tableModelPayloads.getRowCount(), ['', ''])
        # self.appendToResults(str(self._tableModelPayloads.getDataVector()))

    def addToHeader(self, button):
        self._tableModelHeaders.insertRow(self._tableModelHeaders.getRowCount(), ['', ''])

    def addToParams(self, button):
        self._tableModelParams.insertRow(self._tableModelParams.getRowCount(), ['', ''])

    def deleteToPayload(self, button):
        self._tableModelPayloads.removeRow(self._tableModelPayloads.getRowCount()-1)
        # self.appendToResults(str(self._tableModelPayloads.getDataVector()))

    def deleteToHeader(self, button):
        self._tableModelHeaders.removeRow(self._tableModelHeaders.getRowCount()-1)
        # self.appendToResults(str(self._tableModelHeaders.getDataVector()))

    def deleteToParams(self, button):
        self._tableModelParams.removeRow(self._tableModelParams.getRowCount()-1)
        # self.appendToResults(str(self._tableModelParams.getDataVector()))


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
        if not self.status_flag:
            for idx, key in enumerate(self._dictPayloads):
                if "$HEADER$" in key and not self._dictPayloads_headers.get(key) and self._dictPayloads[key] == '1':
                    self._dictPayloads_headers[key] = self._dictPayloads[key]

            for idx, key in enumerate(self._dictPayloads):
                if "$PARAM$" in key and not self._dictPayloads_params.get(key) and self._dictPayloads[key] == '1':
                    self._dictPayloads_params[key] = self._dictPayloads[key]

            self.status_flag = True
            self.submitSearchButton.setBackground(Color.GRAY)
            self.appendToResults("\nProxy start...\n")

        elif self.status_flag:
            self.status_flag = False
            self.submitSearchButton.setBackground(Color.WHITE)
            self.appendToResults("\nProxy stop...\n")


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
        return self.name


    def getUiComponent(self):
        return self._jPanel
