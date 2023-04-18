import re, abc

class IPv4Address:
    def __init__(self, ipv4:str):
        self.ip_addr = ipv4.split(".")
    def __str__(self):
        return "{}.{}.{}.{}".format(self.ip_addr[0], self.ip_addr[1], self.ip_addr[2], self.ip_addr[3])
    
class SSHTime:
    def __init__(self, _value:str) -> None:
        self.month = re.search(r'^/w{3}', _value)
        self.day = re.search(r'(?<=^/w{3} {1,2})/w*', _value)
        self.hour = re.search(r'(?<=^/w{3} {1,2} /w* )/w{2}', _value)
        self.minute = re.search(r'(?<=^/w{3} {1,2} /w* /w{2}:)/w{2}', _value)
        self.second = re.search(r'(?<=^/w{3} {1,2} /w* /w{2}:/w{2}:)/w{2}', _value)
    
    def __str__(self) -> str:
        return "{1} {2} {3}:{4}:{5}".format(self.month, self.day, self.hour, self.minute, self.second)
    

# z3, z4

class SSHLogEntry(metaclass=abc.ABCMeta):
    @abc.abstractclassmethod
    def __init__(self, time:str, raw:str, pid:int, host_name =""):
        self.time=time
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
            if(self.time==re.search(date_pattern, self._raw).group(0) and self.pid==re.search(pid_pattern, self._raw).group(0)):
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
        return "<SSHLogEntry object; time={1}, raw={2}, pid={3}, host_name={4}>".format(self.time, self._raw, self.pid, self.host_name)

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
        
# z7 - TODO
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
        date_pattern = r'(?<=time=).*(?=, raw=)'
        pid_pattern = r'(?<=pid=)\w+'
        host_pattern = r'(?<=host_name=)\w*'
        raw_pattern = r'(?<=raw=).*(?=, pid)'
        temp_time = re.search(date_pattern, _repr).group(0)
        temp_raw = re.search(raw_pattern, _repr).group(0)
        temp_pid = re.search(pid_pattern, _repr).group(0)
        temp_host = re.search(host_pattern, _repr).group(0)
        #if(re.search(host_pattern, _repr)):temp_host = re.search(host_pattern, _repr).group(0)
        self._logs.append(SSHLogEntry(temp_time, temp_raw, temp_pid, temp_host))




# z8 - TODO
class SSHUser:
    def __init__(self, name, last_login):
        self.username=name
        self.last_login=last_login

    def validate(self):
        validation_pattern = r'^[A-z_][A-z0-9_-]{0,31}$'
        if(re.match(validation_pattern, self.username)):
            return True
        else:
            return False