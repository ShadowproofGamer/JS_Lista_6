import datetime, re

# z1 

class IPv4Address:
    def __init__(self, ipv4:str):
        self.ip_addr = ipv4.split(".")
    def __str__(self):
        return "{}.{}.{}.{}".format(self.ip_addr[0], self.ip_addr[1], self.ip_addr[2], self.ip_addr[3])
        


class SSHLogEntry:
    def __init__(self, time:str, description:str, pid:int, host_name =""):
        self.time=time
        self.host_name=host_name
        self.description=description
        self.pid=pid
    
    def __str__(self):
        result = "{}\t\t{}\t\t{}\t\t{}".format(self.time,self.host_name,self.description,str(self.pid))
        return result
    
    def get_ipv4(self):
        ipv4_pattern = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        data = re.search(ipv4_pattern, self.description)
        if(data): return IPv4Address(data[0])
        else: return None

# z2

class SSHLogFailed(SSHLogEntry):
    def __init__(self, time:str, description:str, pid:int, host_name =""):
        super().__init__(time, description, pid, host_name)
        self.user = re.search(r'(?<=Failed password for )\w*', description).group(0)
        self.port = int(re.search(r'(?<=port )\w*', description).group(0))
        self.ssh_nr = re.search(r'ssh2|ssh1|ssh', description).group(0)

class SSHLofAccepted(SSHLogEntry):
    def __init__(self, time:str, description:str, pid:int, host_name =""):
        super().__init__(time, description, pid, host_name)
        self.user = re.search(r'(?<=Accepted password for )\w*', description).group(0)
        self.port = int(re.search(r'(?<=port )\w*', description).group(0))
        self.ssh_nr = re.search(r'ssh2|ssh1|ssh', description).group(0)

class SSHLogError(SSHLogEntry):
    # error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]
    def __init__(self, time:str, description:str, pid:int, host_name =""):
        super().__init__(time, description, pid, host_name)
        self.errno = int(re.search(r'(?<=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}: )\w*(?=:)', description).group(0))
        self.errdsc = re.search(r'(?<=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}: \w*:).*(?= \[)')


class SSHLogOther(SSHLogEntry):
    def __init__(self, time:str, description:str, pid:int, host_name =""):
        super().__init__(time, description, pid, host_name)





























# testy
try: 
    #pobieranie nazwy pliku i danych
    file_path = input()
    file = open(file_path, "r")
    data_lines = [tmp.strip() for tmp in file.readlines()]

    # testowanie klas:
    def to_dict(line:str):
    # Znacznik czasowy, nazwę hosta, komponent aplikacji i numer PID, opis zdarzenia (w tym user)
    # np. Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
        date_pattern = r'^[A-Z][a-z]{2} {1,2}[0-9]{1,2} \w{2}:\w{2}:\w{2}'
        user_pattern = r'(?<=user )\w*|(?<= user=)\w*|(?<=Failed password for )\w*|(?<=Accepted password for )\w*' 
        #komponent_and_pid_pattern = r'[A-Za-z]+\[\w*]:'
        komponent_pattern = r'[A-za-z]+(?=\[\w*]:)'
        pid_pattern = r'(?<=\[)\w*(?=]:)'
        description_pattern = r'(?<=: ).*$'
        host_pattern = r'(?<=:\w\w )\w+'
        #temp = copy.deepcopy(line)
        temp = line
        result = {
            "date": re.search(date_pattern, line).group(0),
            "user": "",
            "komponent": re.search(komponent_pattern, line).group(0),
            "pid": re.search(pid_pattern, line).group(0),
            "description": re.search(description_pattern, line).group(0),
            "host": re.search(host_pattern, line).group(0)
        }
        if(re.search(user_pattern, line)): result["user"] = re.search(user_pattern, line).group(0)
        #print(result)
        return result

    dct = to_dict(data_lines[0])
    sh1 = SSHLogEntry(dct.get("date"), dct.get("description"), dct.get("pid"), dct.get("host"))
    print(sh1)
    print(sh1.get_ipv4())


except Exception:
    print(Exception.with_traceback())