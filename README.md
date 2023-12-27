# CloudTrail Indicators Of Compromise Searcher

This is a work in progress of a CloudTrail IOC searcher. It looks for a few IOCs such as **CreateKeyPair**, **CreateSecurityGroup**, **RunInstances** and **StartInstances**. It provides the *file* where the event is located as well as some of the *elements*. It will also list the **User-Agents** and **Source IP Addresses** found in descending order.

## Getting Started

### Executing program

* With python3
```
python3 cloudtrail.py -f CloudTrail/
```

* Search for User-Agent strings
```
python3 cloudtrail.py -f CloudTrail/ -ua 'aws-cli'
```

* Search for Source IP strings
```
python3 cloudtrail.py -f CloudTrail/ -ip '127.0.0.1'
```

## Help

For help menu:
```
python3 cloudtrail.py -h
```

## Disclaimer
All the code provided on this repository is for educational/research purposes only. Any actions and/or activities related to the material contained within this repository is solely your responsibility. The misuse of the code in this repository can result in criminal charges brought against the persons in question. Author will not be held responsible in the event any criminal charges be brought against any individuals misusing the code in this repository to break the law.