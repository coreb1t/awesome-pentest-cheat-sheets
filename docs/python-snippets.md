# Python Snippets 

## File Operations

* read a file line by line into a list

	* If you want the \n included:

	```python
		with open(fname) as f:
	    	content = f.readlines()
	```

	* If you do not want \n included:

	```python
	with open(fname) as f:
	    content = f.read().splitlines()
	```

* move file to the dist_dir folder
	
		os.rename(<filname>, dist_dir + os.path.sep + <filename>)

* get working directory

		PWD = os.getcwd()

* write file 

		RESOURCE = "filename.txt"
		fd = open(RESOURCE, 'w')
	    fd.write("first line\n")
	    fd.close()


## Parsing Arguments

```python
parser = argparse.ArgumentParser()

parser.add_argument("-p", dest="payload", help=payloads, required=True)
parser.add_argument("-i", dest="interface", help="use interface - default: eth0", default="eth0")
args = parser.parse_args()

payload_type = args.payload
```