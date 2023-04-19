import re, abc

class IPv4Address:
    def __init__(self, ipv4:str):
        self.ip_addr = ipv4.split(".")
    def __str__(self):
        return "{}.{}.{}.{}".format(self.ip_addr[0], self.ip_addr[1], self.ip_addr[2], self.ip_addr[3])
    
class SSHTime:
    def __init__(self, _value:str) -> None:
        self.month = re.search(r'^\w{3}', _value).group(0)
        self.day = re.search(r'(?<=^\w{3} {1})\w*|(?<=^\w{3} {2})\w*', _value).group(0)
        self.hour = re.search(r'(?<=^\w{3} {1}\w{2} )\w{2}|(?<=^\w{3} {2}\w )\w{2}', _value).group(0)
        self.minute = re.search(r'(?<=^\w{3} {1}\w{2} \w{2}:)\w{2}|(?<=^\w{3} {2}\w \w{2}:)\w{2}', _value).group(0)
        self.second = re.search(r'(?<=^\w{3} {1}\w{2} \w{2}:\w{2}:)\w{2}|(?<=^\w{3} {2}\w \w{2}:\w{2}:)\w{2}', _value).group(0)
    
    def __str__(self) -> str:
        return "{} {} {}:{}:{}".format(self.month, self.day, self.hour, self.minute, self.second)
    
    def __eq__(self, other: object) -> bool:
        return (self.month==other.month and self.day==other.day and self.hour==other.hour and self.minute==other.minute and self.second==other.second)
    
    


# z1, z3, z4

class SSHLogEntry(metaclass=abc.ABCMeta):
    @abc.abstractclassmethod
    def __init__(self, time:str, raw:str, pid:int, host_name =""):
        self.time=SSHTime(time)
        self.host_name=host_name
        self._raw=raw
        self.pid=pid
    
    @abc.abstractmethod
    def __str__(self):
        result = "{}\t\t{}\t\t{}\t\t{}".format(self.time,self.host_name,str(self.pid),self._raw)
        return result
    
    @abc.abstractmethod
    def get_ipv4(self):
        ipv4_pattern = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        data = re.search(ipv4_pattern, self._raw)
        if(data): return IPv4Address(data[0])
        else: return None

    @abc.abstractmethod
    def validate(self):
        date_pattern = r'^[A-Z][a-z]{2} {1,2}[0-9]{1,2} \w{2}:\w{2}:\w{2}'
        pid_pattern = r'(?<=\[)\w*(?=]:)'
        try:
            if(str(self.time)==re.search(date_pattern, self._raw).group(0) and self.pid==re.search(pid_pattern, self._raw).group(0)):
                return True
            else:
                return False
        except Exception:
            return False
        
    # z5
    @property
    def has_ip(self):
        if(self.get_ipv4()):
            return True
        else:
            return False
    
    # z6
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogEntry", self.time, self._raw, self.pid, self.host_name)

    def __eq__(self, __value: object) -> bool:
        try: 
            return (self.pid==__value.pid)
        except: 
            return False

    def __gt__(self, _value: object) -> bool:
        try: 
            return (self.pid>_value.pid)
        except: 
            return False

    def __lt__(self, _value:object) -> bool:
        try: 
            return (self.pid<_value.pid)
        except: 
            return False
        

    # z2

class SSHLogFailed(SSHLogEntry):
    def __init__(self, time:str, raw:str, pid:int, host_name =""):
        super().__init__(time, raw, pid, host_name)
        self.user = re.search(r'(?<=Failed password for )\w*', raw).group(0)
        self.port = int(re.search(r'(?<=port )\w*', raw).group(0))
    def __str__(self):
        return super().__str__()
    def get_ipv4(self):
        return super().get_ipv4()
    def validate(self):
        return super().validate()
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogFailed", self.time, self._raw, self.pid, self.host_name)
    def __lt__(self, _value: object) -> bool:
        return super().__lt__(_value)
    def __eq__(self, __value: object) -> bool:
        return super().__eq__(__value)
    def __gt__(self, _value: object) -> bool:
        return super().__gt__(_value)

class SSHLogAccepted(SSHLogEntry):
    def __init__(self, time:str, raw:str, pid:int, host_name =""):
        super().__init__(time, raw, pid, host_name)
        self.user = re.search(r'(?<=Accepted password for )\w*', raw).group(0)
        self.port = int(re.search(r'(?<=port )\w*', raw).group(0))
    def __str__(self):
        return super().__str__()
    def get_ipv4(self):
        return super().get_ipv4()
    def validate(self):
        return super().validate()
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogAccepted", self.time, self._raw, self.pid, self.host_name)
    def __lt__(self, _value: object) -> bool:
        return super().__lt__(_value)
    def __eq__(self, __value: object) -> bool:
        return super().__eq__(__value)
    def __gt__(self, _value: object) -> bool:
        return super().__gt__(_value)

class SSHLogError(SSHLogEntry):
    def __init__(self, time:str, raw:str, pid:int, host_name ="", errno=0, errdsc=""):
        super().__init__(time, raw, pid, host_name)
        #self.errno = int(re.search(r'(?<=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}: )\w*(?=:)', raw).group(0))
        #self.errdsc = re.search(r'(?<=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}: \w*:).*(?= \[)', raw).group(0)
        self.errno=errno
        self.errdsc=errdsc

    def __str__(self):
        return super().__str__()
    def get_ipv4(self):
        return super().get_ipv4()
    def validate(self):
        return super().validate()
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogError", self.time, self._raw, self.pid, self.host_name)
    def __lt__(self, _value: object) -> bool:
        return super().__lt__(_value)
    def __eq__(self, __value: object) -> bool:
        return super().__eq__(__value)
    def __gt__(self, _value: object) -> bool:
        return super().__gt__(_value)


class SSHLogOther(SSHLogEntry):
    def __init__(self, time:str, raw:str, pid:int, host_name =""):
        super().__init__(time, raw, pid, host_name)
    def __str__(self):
        return super().__str__()
    def get_ipv4(self):
        return super().get_ipv4()
    def validate(self):
        return super().validate()
    def __repr__(self) -> str:
        return "<{}; time={}, raw={}, pid={}, host_name={}>".format("SSHLogOther", self.time, self._raw, self.pid, self.host_name)
    def __lt__(self, _value: object) -> bool:
        return super().__lt__(_value)
    def __eq__(self, __value: object) -> bool:
        return super().__eq__(__value)
    def __gt__(self, _value: object) -> bool:
        return super().__gt__(_value)
        
# z7
class SSHLogJournal:
    def __init__(self):
        self._logs=list()
    
    def __len__(self):
        return len(self._logs)
    
    def __iter__(self):
        yield from self._logs

    def __contains__(self, _value):
        for i in self._logs:
            if(i==_value):
                return True
        return False

    def append(self, _repr:str):
        type_pattern = r'(?<=<)[a-zA-Z]*(?=;)'
        date_pattern = r'(?<=time=).*(?=, raw=)'
        pid_pattern = r'(?<=pid=)\w+'
        host_pattern = r'(?<=host_name=)\w*'
        raw_pattern = r'(?<=raw=).*(?=, pid)'
        #print(re.search(date_pattern, _repr))
        temp_type = re.search(type_pattern, _repr).group(0)
        temp_time = re.search(date_pattern, _repr).group(0)
        temp_raw = re.search(raw_pattern, _repr).group(0)
        temp_pid = re.search(pid_pattern, _repr).group(0)
        temp_host = re.search(host_pattern, _repr).group(0)
        #if(re.search(host_pattern, _repr)):temp_host = re.search(host_pattern, _repr).group(0)
        if temp_type=="SSHLogFailed":
            new_object = SSHLogFailed(temp_time, temp_raw, temp_pid, temp_host)
            if(new_object.validate()):
                self._logs.append(new_object)
        elif temp_type=="SSHLogAccepted":
            new_object = SSHLogAccepted(temp_time, temp_raw, temp_pid, temp_host)
            if(new_object.validate()):
                self._logs.append(new_object)
        elif temp_type =="SSHLogError":
             new_object = SSHLogError(temp_time, temp_raw, temp_pid, temp_host)
             if(new_object.validate()):
                self._logs.append(new_object)
        
        
    
    def logs_by_ip(self, ip:str):
        temp_list = []
        for i in self._logs:
            if(i.get_ipv4()):
                if(str(i.get_ipv4())==ip):
                    temp_list.append(i)
        return temp_list





# z8
class SSHUser:
    def __init__(self, name, last_login:SSHTime):
        self.username=name
        self.last_login=last_login

    def validate(self):
        validation_pattern = r'^[A-z_][A-z0-9_-]{0,31}$'
        if(re.match(validation_pattern, self.username)):
            return True
        else:
            return False
    

# demonstracja:
container = SSHLogJournal()
test1 = SSHLogError("Dec 10 11:03:44", "Dec 10 11:03:44 LabSZ sshd[25455]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]", 25455, "LabSZ", 14, "No more user authentication methods available.")
test2 = SSHLogFailed("Dec 10 06:55:48", "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2", 24200, "LabSZ")
test3 = SSHLogAccepted("Dec 10 09:32:20", "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2", 24680, "LabSZ")
test4 = SSHUser("root", SSHTime("Jan  7 16:55:18"))

print(SSHTime("Dec 10 11:03:44").month)
print(repr(test1))
print(test1)
print(test2)
print(test3)


container.append(repr(test1))
container.append(repr(test2))
container.append(repr(test3))

lista=[]
for i in container:
    lista.append(i)

lista.append(test4)
index=1
for i in lista:
    print("test"+str(index), i.validate())
    index+=1

