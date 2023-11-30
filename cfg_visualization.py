# CFG Visualization 
#
#@author Kevin, Max, Valerie
#@category csce451.c3
#
#

# Import necessary modules
import os
import tempfile
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
from javax.swing import JScrollPane, JFrame, ImageIcon, JLabel
from java.awt import BorderLayout
from java.io import File
from javax.imageio import ImageIO
from ghidra.program.model.listing import Listing;
from ghidra.program.database.code import InstructionDB

# Function to generate DOT file for control flow graph
def generate_cfg_dot():
    bbm = BasicBlockModel(currentProgram)
    blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)

    dot_syntax = "digraph ControlFlow {\n"

    # Dictionary to store function nodes
    function_nodes = {}

    # Set to store nodes with incoming edges
    nodes_with_incoming_edges = set()

    setup_teardown_funcs = ["_start", "main", "_fini", "frame_dummy", "_init", "register_tm_clones",
                            "__do_global_dtors_aux", "__cxa_finalize", "__static_initialization_and_destruction_0",
                            "deregister_tm_clones", "__cxa_atexit", "Init"]
    setup_teardown_blocks = []

    # Loop through each block in the program
    for block in blocks:
        block_address = block.getMinAddress()
        block_name = "BB_" + block_address.toString()

        # Get the function containing the block
        containing_function = getFunctionContaining(block_address)
        function_name = containing_function.getName() if containing_function else "UnknownFunction"
        if function_name in setup_teardown_funcs:
            setup_teardown_blocks.append(block)

        # Build label for the block
        label = '{}():\\n{}\n{}'.format(function_name, block_name, get_block_instructions(block))
        label += " " + block.getFlowType().toString()
        dot_syntax += '    {} [label="{}"];\n'.format(block_name, label)
        
        # Store function nodes for later use
        function_nodes[function_name] = block_name

        instructions = currentProgram.getListing().getInstructions(block, True)
        last_instruction = None
        for instruction in instructions:
            last_instruction = instruction
        
        next_block_start = last_instruction.getNext()
        #print(next_block_start)


        # if block.getNumSources(TaskMonitor.DUMMY) == 0:
        #     nodes_with_no_incoming_edges.add(block)

        successors = block.getDestinations(TaskMonitor.DUMMY)
        while successors.hasNext():
            successor = successors.next()
            successor_address = successor.getDestinationAddress()
            successor_name = "BB_" + successor_address.toString()
            nodes_with_incoming_edges.add(successor)

            reference_type = successor.getFlowType()
            edge_label = ""

            if reference_type.isCall():
                edge_label = "call"
            elif reference_type.isConditional():               
                edge_label = "else"
            elif reference_type.hasFallthrough() and block.getFlowType().isConditional():
                edge_label = "if"

            dot_syntax += '    {} -> {} [label="{}"];\n'.format(block_name, successor_name, edge_label)

    # Highligh nodes without incoming edges in red
    function_name_noedge = []
    print(setup_teardown_blocks)
    blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)
    for block in blocks:
        if block not in nodes_with_incoming_edges and block not in setup_teardown_blocks:
            block_address = block.getMinAddress()
            block_name = "BB_" + block_address.toString()
            containing_function = getFunctionContaining(block_address)
            function_name = containing_function.getName() if containing_function else "UnknownFunction"
            dot_syntax += '    {} [label="{}", color=red];\n'.format(block_name, '{}():\\n{}'.format(function_name, block_name))
            function_name_noedge.append(function_name)

    dot_syntax += "}\n"

    dot_filename = "C:\Users\maxma\Documents\School\Masters\csce_652\C3\ControlFlowGraph.dot"
    with open(dot_filename, "w") as dot_file:
        dot_file.write(dot_syntax)

    display_dot_file(dot_filename)

    print("Control flow graph DOT file generated: {}".format(dot_filename))

def get_block_instructions(block):
    instructions = currentProgram.getListing().getInstructions(block, True)
    instruction_text = ""
    
    for instruction in instructions:
        instruction_text += instruction.toString() + "\\n"

    return instruction_text


def display_dot_file(dot_file_path):
    try:
        png_filename = dot_file_path.replace(".dot", ".png")
        os.system("circo dot -Tpng -Gdpi=300 -Gsize=12,15\! -o {} {}".format(png_filename, dot_file_path))

        image = ImageIO.read(File(png_filename))
        label = JLabel(ImageIcon(image))
        scroll_pane = JScrollPane(label)

        frame = JFrame("Control Flow Graph")
        frame.getContentPane().add(scroll_pane, BorderLayout.CENTER)
        frame.setSize(800, 600)  
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        frame.setVisible(True)

    except Exception as e:
        print("An error occurred: {}".format(e))

os.system("sudo apt install graphviz")
generate_cfg_dot()

