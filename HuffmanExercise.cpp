#define _CRT_SECURE_NO_WARNINGS

//Uncomment the below line to display general debug information (in most cases only for the first few operations) or the Huffman table.
//#define DEBUG

#include <fstream>
#include <algorithm>
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <stack>
#include <assert.h>
using namespace std;

struct node {
	char symbol;
	int frequency;
	node *left, *right;
};
bool comp(const node* a, const node* b) { return a->frequency < b->frequency; }

node* join(node* a, node* b) {
	node* newNode = new node;
	newNode->frequency = a->frequency + b->frequency;
        #ifdef DEBUG
		cout << "New node " << a->symbol << b->symbol << " has frequency " << newNode->frequency << endl;
    #endif
	newNode->left = a;
	newNode->right = b;
	return newNode;
}

void buildHuffmanTable(map<char, string> &huffmanTable, const node* currNode, const string& prefix = "") {
	if (currNode->left != NULL) buildHuffmanTable(huffmanTable, currNode->left, prefix + '0');
	if (currNode->right != NULL) buildHuffmanTable(huffmanTable, currNode->right, prefix + '1');
	huffmanTable[currNode->symbol] = prefix; //At this line we're guaranteed to be in a leaf node with a unique prefix for its symbol.
}

//Uses depth-first, post-order tree traversal to write the tree to a file outputTree.txt.
void writeTree(ofstream& outputFile, const node* currNode) { 
	if (currNode->left != NULL) writeTree(outputFile, currNode->left);
	if (currNode->right != NULL) writeTree(outputFile, currNode->right);
	//Build a char* of data to write to file.
	char* byteArr = new char[4];
	byteArr[0] = currNode->symbol;
	byteArr[1] = currNode->frequency + '0';
	byteArr[2] = (currNode->left != NULL) ? '1' : '0'; //Has left child?
	byteArr[3] = (currNode->right != NULL) ? '1' : '0'; //Has right child?
	outputFile.write(byteArr, 4);
}

int main(int argc, char** argv)  {

	if (argc < 2) {
		cout << "\nInput error: provide the filename of the data to be encrypted.\n"
			<< "The final message can be found in the file \"output\".\n";
		return 0;
	}

	//Primary variables.
	int operationInfoLimit = 10;
	streampos messageSize;
	char* message("");
	char* sortedMessage("");
	char* encryptedMessage("");
	char* numTrashBits("");
	vector<node*> forest;
	ifstream inputFile;
	ofstream outputFile;

	inputFile.open(argv[1], ios::in | ios::binary | ios::ate); //Open in binary mode. Getline() and << >> will not work now.
	if (inputFile.is_open()) {
		//Loop through all bytes using ifstream object's read(char* to send to, number bytes to read) method.
		//RECALL THAT ANY BYTE <=> A CHAR. There are then only 256 possibilities.
		//Ergo, read one byte at a time (second arg) until hitting EOF.
		messageSize = inputFile.tellg(); //Returns total bytes in file--this is why we opened at end (ios::ate).
		message = new char[(int)messageSize];
		inputFile.seekg(0); //Move parsing back to beginning.
		inputFile.read(message, messageSize);
	}
	else { cout << "Error opening input file with name: " << argv[1] << endl; inputFile.close(); return 0; }
	inputFile.close();

	//First, sort the message using an O(n log n) sort to help enable our second step's logic (though it costs a potentially large string copy operation).
	sortedMessage = new char[(int)messageSize];
	for (int i = 0; i < messageSize; ++i) sortedMessage[i] = message[i];
	sort(sortedMessage, sortedMessage + (int)messageSize);

	//Second, loop the result and add a new binary tree struct for every newly found char, else increment an old one's frequency.
	char prev;
	for (int i = 0; i < messageSize; ++i) {
		if (i == 0 || sortedMessage[i] != prev) {
			//Create new binary tree node struct.
			node* n = new node;
			n->symbol = sortedMessage[i];
			n->frequency = 1;
			n->left = n->right = NULL;
			forest.push_back(n);
		}
		else ++forest[forest.size() - 1]->frequency; //Increment the frequency for that unique byte.

		prev = sortedMessage[i];
	}

#ifdef DEBUG
	cout << "Original message: " << message << endl;
	cout << "Sorted message: " << sortedMessage << endl;
	cout << "\nSingleton trees inside forest--index, symbol, frequency:\n";
	for (int i = 0; i < forest.size(); ++i) cout << i << ": " << forest[i]->symbol << " " << forest[i]->frequency << endl;
	cout << "\nBeginning join operations:\n";
#endif

	//Third, iterate the forest until 1 tree, the Huffman tree, remains.
	int huffmanTreeCountAndTableLength = forest.size();
	while (forest.size() != 1) {
		//Find the two lowest frequency nodes.
		sort(forest.begin(), forest.end(), comp); //INEFFICIENT, might return later to manually code in a sort that'll take advantage of the partial sorting this leads to, since only 2 elements change around each iteration.
		forest.push_back(join(forest[0], forest[1])); //Join the two, and push back the result of their joining, actually removing (via erase-remove) the two distinct nodes.
		forest.erase(remove(forest.begin(), forest.end(), forest[0]), forest.end());
		forest.erase(remove(forest.begin(), forest.end(), forest[0]), forest.end()); //NOT forest[1] because we just shifted everything once.
	}
	assert(forest.size() == 1); //Only the Huffman tree should remain in the forest as a singleton vector.
	assert(forest[0]->frequency == messageSize); //Total frequency of said tree should be equal to the total number of bytes from original message.

	//Fourth, build the Huffman table whose elements correspond to the prefix codes.
	map<char, string> huffmanTable; //Alternately could try a direct address table of strings to speed accesses, but looking to become more familiar with <map>, plus O(log n) is still great!
	buildHuffmanTable(huffmanTable, forest[0]); //Will fill in the rows of huffmanTable with prefix codes, each row gets one that stands for a unique byte symbol.

#ifdef DEBUG
	cout << "\nHuffman table contents:\n";
	for (auto iter = huffmanTable.cbegin(); iter != huffmanTable.cend(); ++iter) cout << iter->first << ' ' << iter->second << endl; //Auto just fills in the right iter type for you.
	cout << endl;
	cout << "Begin monitoring of the encrypted message's writing loop:\n";
#endif

	//Fifth, serialize the tree to be sent to the other end that's getting the encrypted message.
	outputFile.open("serializedTree.txt", ios::out | ios::binary);
	if (outputFile.is_open()) writeTree(outputFile, forest[0]);
	else { cout << "Error in creating or writing to serializedTree.txt!\n"; outputFile.close(); return 0; }
	outputFile.close();

	//Sixth and finally, encrypt the message and print result.
	char* byteArr = new char[1];
	byteArr[0] = 0;
	int bitPos = 7;
	outputFile.open("encryptedMessage.txt", ios::out | ios::binary);
	if (outputFile.is_open()) {
		for (int i = 0; i < messageSize; ++i) {
			string code = huffmanTable[message[i]]; //Ready the next prefix code to be written.
			for (unsigned int j = 0; j < code.length(); ++j) {
				byteArr[0] |= (code[j] - '0') << bitPos; //Convert a prefix char to int, then left shift the bit bitPos times, and then OR-ing it into the current bitstring in byteArr.
#ifdef DEBUG
				if (i < operationInfoLimit) cout << bitPos << ".) byteArr[0]: " << (int)byteArr[0] << endl;
#endif
				bitPos--;
				if (bitPos < 0) { //We have a full byte ready to be written.
#ifdef DEBUG
					if (i < operationInfoLimit) cout << "Writing byteArr[0] to file.\n";
#endif
					outputFile.write(byteArr, 1);
					bitPos = 7;
					byteArr[0] = 0;
				}
			}
		}

		if (bitPos != 7) outputFile.write(byteArr, 1); //Remaining bits leftover in byteArray are left as zeroes just to keep it a byte in length.
		byteArr[0] = (bitPos == 7) ? 0 : bitPos + 1; //bitPos+1 is now equal to the number of trash bits, so we can use it to keep from reading said padding.
#ifdef DEBUG
		cout << "Wrote byteArr[0] to the file with " << (int)byteArr[0] << " trash bits.\n";
		cout << "Writing the number of trash bits to file.\n";
#endif
		outputFile.write(byteArr, 1);
	}
	else { cout << "Error in creating or writing to encryptedMessage.txt!\n"; outputFile.close(); return 0; }
	outputFile.close();

	/*END OF ENCRYPTION CODE - START OF DECRYPTION CODE*/

	//In decryption, first unserialize the tree (the order should be symbol, frequency, hasLeft, hasRight) via stack.
	stack<node*> stack;
	inputFile.open("serializedTree.txt", ios::in | ios::binary);
	if (inputFile.is_open()) {
		while (inputFile) {
			node* n = new node;
			inputFile.read(byteArr, 1); n->symbol = byteArr[0];
			inputFile.read(byteArr, 1); n->frequency = byteArr[0] - '0'; //Could skip serializing this, but included it for completeness.
			inputFile.read(byteArr, 1); bool hasLeft = byteArr[0] - '0';
			inputFile.read(byteArr, 1); bool hasRight = byteArr[0] - '0';
			if (!(hasLeft || hasRight)) {
				n->left = n->right = NULL;
				stack.push(n); //If n is a leaf, push on stack.
			}
			else if (stack.size() - 1 > 0) { //This is to exit when we only have the root left.
				//If n is an internal node, pop 2 children from stack, push node on.
				n->right = stack.top(); stack.pop();
				n->left = stack.top(); stack.pop();
				stack.push(n);
			} //Root should be left at end, so use stack.top() to access the Huffman tree for decryption.
		}
	}
	else { cout << "Error opening serializedTree.txt!\n"; inputFile.close(); return 0; }
	inputFile.close();

	//Second and finally, use the restored tree to decrypt the encrypted message.
	inputFile.open("encryptedMessage.txt", ios::in | ios::binary | ios::ate);
	if (inputFile.is_open()) {
		messageSize = inputFile.tellg(); //This is in bytes, not bits.
		inputFile.seekg(messageSize - (streampos)1); //The get position is a byte from the end, at bitPos.
		numTrashBits = new char[1];
		inputFile.read(numTrashBits, 1);
		assert((int)(*numTrashBits) == (bitPos == 7) ? 0 : bitPos + 1);
		messageSize -= 1; //To exclude bitPos, i.e. numTrashBits, itself.
		encryptedMessage = new char[(int)messageSize];
		inputFile.seekg(0);
		inputFile.read(encryptedMessage, messageSize); //Trash bits included.
	}
	else { cout << "Error opening encryptedMessage.txt!\n"; inputFile.close();  return 0; }
	inputFile.close();
	
	FILE *f = fopen("output", "wb"); // outputFile.open("output", ios::out | ios::binary); 
	if (f != NULL) { // if (outputFile.is_open()) {
		node* n = stack.top();
		for (int i = 0; i < messageSize; ++i) { //For each byte in the encrypted message...
			int currentByte = encryptedMessage[i];
			for (int bitPos = 7; bitPos >= ((i == (int)messageSize - 1) ? (int)(*numTrashBits) : 0); --bitPos) { //Conditional activates in final byte.
				int result = currentByte & 1 << bitPos; //Reads bit by bit by AND-ing encryptedMessage[i] with a mask.
				if (result == 0 && n->left != NULL) n = n->left;
				else if (result != 0 && n->right != NULL) n = n->right;
				if (n->left == NULL && n->right == NULL) { //Any time a leaf node is reached, write the symbol, end of code!
					byteArr[0] = n->symbol;
					#ifdef DEBUG
					if (i < operationInfoLimit) {
						cout << "Wrote " << n->symbol << "to output.\n";
						cout << "byteArr[0]: " << (int)byteArr[0] << endl;
					}
					#endif
					putc(byteArr[0], f);
					n = stack.top();
				}
			}
		}
	} else { cout << "Error creating or writing to output file!\n"; fclose(f); return 0; }
	fclose(f); //outputFile.close();
	

	delete[] message;
	delete[] sortedMessage;
	delete[] byteArr;
	delete[] numTrashBits;
	delete[] encryptedMessage;
}