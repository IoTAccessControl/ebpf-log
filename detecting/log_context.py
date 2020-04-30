# coding: utf-8
import json
import datetime

__author__ = "fripSide"

"""
将IOT操作抽象为：
1. 修改属性
2. 

"""

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

class DataClass(type):

	def __new__(cls, name, bases, attrs):
		mappings = dict()
		for k, v in attrs.items():
			if isinstance(v, DataField):
				mappings[k] = v
		for k in mappings.keys():
			attrs.pop(k)
		attrs["__mappings__"] = mappings
		attrs["__data__"] = name
		return type.__new__(cls, name, bases, attrs)

class DataField:
	# 需要json格式化的字段

	def __init__(self, name, desc=""):
		self.name = name
		self.desc = desc

	def __str__(self):
		return '<%s:%s>'.format(self.__class__.__name__, self.name)

class JsonData(dict, metaclass=DataClass):

	def __init__(self, **kwargs):
		super(JsonData, self).__init__(**kwargs)

	def __setattr__(self, key, value):
		self[key] = value

	def __getattr__(self, key):
		try:
			return self[key]
		except KeyError:
			raise AttributeError(r"'{}' object has no attribute '{}'".format(self.__data__, key))

	def get_fileds(self, ignore_none=False):
		data = {}
		for key in self.__mappings__.keys():
			val = getattr(self, key, None)
			if ignore_none and val is None:
				continue
			if isinstance(val, JsonData):
				val = val.get_fileds()
			data[key] = val
		return data

	def to_json(self, ignore_none=False):
		data = self.get_fileds(ignore_none)
		data = json.dumps(data)
		# print(data)
		return data

class LogEntry(JsonData):
	# log字段
	timestamp = DataField("timestamp")
	host_addr = DataField("host_addr")
	target_addr = DataField("target_addr")
	action = DataField("action")
	properties = DataField("properties")
	target_device = DataField("target_device")

	def __init__(self, **kwargs):
		self.properties = {}
		super(LogEntry, self).__init__(**kwargs)
		self.set_log_ti()

	def set_log_ti(self):
		self.timestamp = ti_to_str(datetime.datetime.now())

def ti_to_str(ti):
	return ti.strftime(TIME_FORMAT)


def str_to_ti(ts):
	return datetime.datetime.strptime(ts, TIME_FORMAT)

	
class LogContext:
	pass


class LogWriter:

	def __init__(self):
		tag = self.__get_timestamp()
		self.fp = open(f"iot-log/{tag}.log", "w")

	def __get_timestamp(self):
		ti = datetime.datetime.now()
		return ti.strftime("%Y%m%d%H%M%S")

	def append_log(self, log_entry):
		data = log_entry.to_json()
		self.fp.write(data)
		self.fp.write("\n")
		self.fp.flush()

	def __del__(self):
		self.fp.close()


def main_test():
	# test meta class
	entry = LogEntry(host_addr="host_addr", properties={})
	entry.target_device = "xxx"
	print(entry.to_json())
	# print(entry.tt)
	print(entry.__dict__)
	for k,v in entry.items():
		print(k, v)
	ts = ti_to_str(datetime.datetime.now())
	print(ts)
	print(str_to_ti(ts))


if __name__ == "__main__":
	main_test()
