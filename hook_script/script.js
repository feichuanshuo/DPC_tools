// 绕过TracerPid检测
var ByPassTracerPid = function () {
    var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        var bufstr = Memory.readUtf8String(buffer);
        if (bufstr.indexOf('TracerPid:') > -1) {
            Memory.writeUtf8String(buffer, 'TracerPid:\t0');
            console.log('tracerpid replaced: ' + Memory.readUtf8String(buffer));
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));
};

// 获取调用链
function getStackTrace() {
    var Exception = Java.use('java.lang.Exception');
    var ins = Exception.$new('Exception');
    var straces = ins.getStackTrace();
    if (undefined == straces || null == straces) {
        return;
    }
    var result = '';
    for (var i = 0; i < straces.length; i++) {
        var str = '   ' + straces[i].toString();
        result += str + '\r\n';
    }
    Exception.$dispose();
    return result;
}

function get_format_time() {
    var myDate = new Date();

    return myDate.getFullYear() + '-' + myDate.getMonth() + '-' + myDate.getDate() + ' ' + myDate.getHours() + ':' + myDate.getMinutes() + ':' + myDate.getSeconds();
}

//告警发送
function alertSend(action, messages, arg) {
    var _time = get_format_time();
    send({
        'type': 'notice',
        'time': _time,
        'action': action,
        'messages': messages,
        'arg': arg,
        'stacks': getStackTrace()
    });
}

// 增强健壮性，避免有的设备无法使用 Array.isArray 方法
if (!Array.isArray) {
    Array.isArray = function (arg) {
        return Object.prototype.toString.call(arg) === '[object Array]';
    };
}

// hook方法
function hookMethod(targetClass, targetMethod, targetArgs, action, messages) {
    try {
        var _Class = Java.use(targetClass);
    } catch (e) {
        return false;
    }

    if (targetMethod == '$init') {
        var overloadCount = _Class.$init.overloads.length;
        for (var i = 0; i < overloadCount; i++) {
            _Class.$init.overloads[i].implementation = function () {
                var temp = this.$init.apply(this, arguments);
                // 是否含有需要过滤的参数
                var argumentValues = Object.values(arguments);
                if (Array.isArray(targetArgs) && targetArgs.length > 0 && !targetArgs.every(item => argumentValues.includes(item))) {
                    return null;
                }
                var arg = '';
                for (var j = 0; j < arguments.length; j++) {
                    arg += '参数' + j + '：' + JSON.stringify(arguments[j]) + '\r\n';
                }
                if (arg.length == 0) arg = '无参数';
                else arg = arg.slice(0, arg.length - 1);
                alertSend(action, messages, arg);
                return temp;
            }
        }
    } else {
        try {
            // 给出方法的重载数量
            var overloadCount = _Class[targetMethod].overloads.length;
        } catch (e) {
            console.log(e)
            console.log('[*] hook(' + targetMethod + ')方法失败,请检查该方法是否存在！！！');
            return false;
        }
        for (var i = 0; i < overloadCount; i++) {
            _Class[targetMethod].overloads[i].implementation = function () {
                // 调用原始方法，并将结果保存到变量temp
                var temp = this[targetMethod].apply(this, arguments);
                // 是否含有需要过滤的参数
                var argumentValues = Object.values(arguments);
                if (Array.isArray(targetArgs) && targetArgs.length > 0 && !targetArgs.every(item => argumentValues.includes(item))) {
                    return null;
                }
                var arg = '';
                for (var j = 0; j < arguments.length; j++) {
                    arg += '参数' + j + '：' + JSON.stringify(arguments[j]) + '\r\n';
                }
                if (arg.length == 0) arg = '无参数';
                else arg = arg.slice(0, arg.length - 1);
                alertSend(action, messages, arg);
                return temp;
            }
        }
    }
    return true;
}

// hook方法(去掉不存在方法）
function hook(targetClass, methodData) {
    try {
        var _Class = Java.use(targetClass);
    } catch (e) {
        return false;
    }
    var methods = _Class.class.getDeclaredMethods();
    _Class.$dispose;
    // 排查掉不存在的方法，用于各个android版本不存在方法报错问题。
    methodData.forEach(function (methodData) {
        for (var i in methods) {
            if (methods[i].toString().indexOf('.' + methodData['methodName'] + '(') != -1 || methodData['methodName'] == '$init') {
                hookMethod(targetClass, methodData['methodName'], methodData['args'], methodData['action'], methodData['messages']);
                break;
            }
        }
    });
}

// hook获取其他app信息api，排除app自身
function hookApplicationPackageManagerExceptSelf(targetMethod, action) {
    var _ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
    try {
        try {
            var overloadCount = _ApplicationPackageManager[targetMethod].overloads.length;
        } catch (e) {
            return false;
        }
        for (var i = 0; i < overloadCount; i++) {
            _ApplicationPackageManager[targetMethod].overloads[i].implementation = function () {
                var temp = this[targetMethod].apply(this, arguments);
                var arg = '';
                for (var j = 0; j < arguments.length; j++) {
                    if (j === 0) {
                        var string_to_recv;
                        send({'type': 'app_name', 'data': arguments[j]});
                        recv(function (received_json_object) {
                            string_to_recv = received_json_object.my_data;
                        }).wait();
                    }
                    arg += '参数' + j + '：' + JSON.stringify(arguments[j]) + '\r\n';
                }
                if (arg.length == 0) arg = '无参数';
                else arg = arg.slice(0, arg.length - 1);
                if (string_to_recv) {
                    alertSend(action, {
                        'detail': targetMethod + '获取的数据为：' + temp,
                        'smallType': '应用信息',
                        'bigType': '设备信息'
                    }, arg);
                }
                return temp;
            }
        }
    } catch (e) {
        console.log(e);
        return
    }


}

// 获取电话相关信息
function getPhoneState() {
    var action = '获取电话相关信息';

    hook('android.telephony.TelephonyManager', [
        // Android 8.0
        {
            'methodName': 'getDeviceId',
            'action': action,
            'messages': {
                'detail': '获取手机与通讯相关的状态和信息，返回唯一的设备ID。如果是GSM网络，返回IMEI；如果是CDMA网络，返回MEID；如果设备ID是不可用的返回null。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        // Android 8.1、9   android 10获取不到
        {
            'methodName': 'getImei',
            'action': action,
            'messages': {
                'detail': '获取IMEI。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getDeviceSoftwareVersion',
            'action': action,
            'messages': {
                'detail': '读取设备的软件版本号，例如IMEI.SV之于GSM电话。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getMeid',
            'action': action,
            'messages': {
                'detail': '获取MEID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getLine1Number',
            'action': action,
            'messages': {
                'detail': '获取手机号码。',
                'smallType': '手机号码',
                'bigType': '个人基本信息'
            }
        },
        {
            'methodName': 'getSimSerialNumber',
            'action': action,
            'messages': {
                'detail': '获取IMSI/iccid。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getSubscriberId',
            'action': action,
            'messages': {
                'detail': '获取SIM卡唯一标识IMSI（国际移动用户识别码）。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getSimOperator',
            'action': action,
            'messages': {
                'detail': '获取MCC/MNC。',
                'smallType': '国家地区',
                'bigType': '个人基本信息'
            }
        },
        {
            'methodName': 'getNetworkOperator',
            'action': action,
            'messages': {
                'detail': '获取MCC/MNC。',
                'smallType': '国家地区',
                'bigType': '个人基本信息'
            }
        },
        {
            'methodName': 'getSimCountryIso',
            'action': action,
            'messages': {
                'detail': '获取SIM卡国家代码。',
                'smallType': '国家地区',
                'bigType': '个人基本信息'
            }
        },
        {
            'methodName': 'getCellLocation',
            'action': action,
            'messages': {
                'detail': '获取电话当前位置信息。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getAllCellInfo',
            'action': action,
            'messages': {
                'detail': '获取电话当前位置信息。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
    ]);

    // 短信
    hook('android.telephony.SmsManager', [
        {
            'methodName': 'sendTextMessageInternal',
            'action': action,
            'messages': {
                'detail': '获取短信信息-发送短信。',
                'smallType': '短信',
                'bigType': '通讯信息'
            }
        },
        {
            'methodName': 'getDefault',
            'action': action,
            'messages': {
                'detail': '获取短信信息-发送短信。',
                'smallType': '短信',
                'bigType': '通讯信息'
            }
        },
        {
            'methodName': 'sendTextMessageWithSelfPermissions',
            'action': action,
            'messages': {
                'detail': '获取短信信息-发送短信。',
                'smallType': '短信',
                'bigType': '通讯信息'
            }
        },
        {
            'methodName': 'sendMultipartTextMessageInternal',
            'action': action,
            'messages': {
                'detail': '获取短信信息-发送短信。',
                'smallType': '短信',
                'bigType': '通讯信息'
            }
        },
        {
            'methodName': 'sendDataMessage',
            'action': action,
            'messages': {
                'detail': '获取短信信息-发送短信。',
                'smallType': '短信',
                'bigType': '通讯信息'
            }
        },
        {
            'methodName': 'sendDataMessageWithSelfPermissions',
            'action': action,
            'messages': {
                'detail': '获取短信信息-发送短信。',
                'smallType': '短信',
                'bigType': '通讯信息'
            }
        },
    ]);

}

// 系统信息(AndroidId/标识/content敏感信息)
function getSystemData() {
    var action = '获取系统信息';

    // hook('android.provider.Settings$Secure', [
    //     {
    //         'methodName': 'getString',
    //         'args': ['android_id'],
    //         'action': action,
    //         'messages': {
    //             'detail': '获取安卓ID。',
    //             'smallType': '设备标识符',
    //             'bigType': '设备信息'
    //         }
    //     }
    // ]);
    hook('android.provider.Settings$System', [
        {
            'methodName': 'getString',
            'args': ['android_id'],
            'action': action,
            'messages': {
                'detail': '获取安卓ID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        }
    ]);

    hook('android.os.Build', [
        {
            'methodName': 'getSerial',
            'action': action,
            'messages': {
                'detail': '获取设备序列号。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('android.app.admin.DevicePolicyManager', [
        {
            'methodName': 'getWifiMacAddress',
            'action': action,
            'messages': {
                'detail': '获取设备的MAC地址。',
                'smallType': 'MAC信息',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('android.content.ClipboardManager', [
        {
            'methodName': 'getPrimaryClip',
            'action': action,
            'messages': {
                'detail': '读取剪切板信息。',
                'smallType': '剪切板',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'setPrimaryClip',
            'action': action,
            'messages': {
                'detail': '写入剪切板信息。',
                'smallType': '剪切板',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('android.telephony.UiccCardInfo', [
        {
            'methodName': 'getIccId',
            'action': action,
            'messages': {
                'detail': '获取手机IccId信息.',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
    ]);

    //小米
    hook('com.android.id.impl.IdProviderImpl', [
        {
            'methodName': 'getUDID',
            'action': action,
            'messages': {
                'detail': '读取小米手机UDID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getOAID',
            'action': action,
            'messages': {
                'detail': '读取小米手机UDID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getVAID',
            'action': action,
            'messages': {
                'detail': '读取小米手机VAID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getAAID',
            'action': action,
            'messages': {
                'detail': '读取小米手机AAID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
    ]);

    //三星
    hook('com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy', [
        {
            'methodName': 'getOAID',
            'action': action,
            'messages': {
                'detail': '读取三星手机OAID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getVAID',
            'action': action,
            'messages': {
                'detail': '读取三星手机VAID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getAAID',
            'action': action,
            'messages': {
                'detail': '读取三星手机AAID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('repeackage.com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy', [
        {
            'methodName': 'getOAID',
            'action': action,
            'messages': {
                'detail': '读取三星手机OAID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getVAID',
            'action': action,
            'messages': {
                'detail': '读取三星手机VAID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getAAID',
            'action': action,
            'messages': {
                'detail': '读取三星手机AAID。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
    ]);

    //获取content敏感信息
    try {
        // 通讯录内容
        var ContactsContract = Java.use('android.provider.ContactsContract');
        var contact_authority = ContactsContract.class.getDeclaredField('AUTHORITY').get('java.lang.Object');
    } catch (e) {
        console.log(e)
    }
    try {
        // 日历内容
        var CalendarContract = Java.use('android.provider.CalendarContract');
        var calendar_authority = CalendarContract.class.getDeclaredField('AUTHORITY').get('java.lang.Object');
    } catch (e) {
        console.log(e)
    }
    try {
        // 相册内容
        var MediaStore = Java.use('android.provider.MediaStore');
        var media_authority = MediaStore.class.getDeclaredField('AUTHORITY').get('java.lang.Object');
    } catch (e) {
        console.log(e)
    }
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        var queryLength = ContentResolver.query.overloads.length;
        for (var i = 0; i < queryLength; i++) {
            ContentResolver.query.overloads[i].implementation = function () {
                var temp = this.query.apply(this, arguments);
                if (arguments[0].toString().indexOf(contact_authority) != -1) {
                    alertSend(action, {
                        'detail': '获取手机通信录内容。',
                        'smallType': '通信录',
                        'bigType': '通讯信息'
                    }, '');
                } else if (arguments[0].toString().indexOf(calendar_authority) != -1) {
                    alertSend(action, {
                        'detail': '获取日历内容。',
                        'smallType': '手机日历',
                        'bigType': '设备信息'
                        }, '');
                } else if (arguments[0].toString().indexOf(media_authority) != -1) {
                    alertSend(action, {
                        'detail': '获取相册内容。',
                        'smallType': '相册',
                        'bigType': '媒体信息'
                    }, '');
                }
                return temp;
            }
        }
    } catch (e) {
        console.log(e);
        return
    }
}

//获取其他app信息
function getPackageManager() {
    var action = '获取其他app信息';

    hook('android.content.pm.PackageManager', [
        {
            'methodName': 'getInstalledPackages',
            'action': action,
            'messages': {
                'detail': '获取已安装应用程序列表。',
                'smallType': '应用程序列表',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getInstalledApplications',
            'action': action,
            'messages': {
                'detail': '获取已安装应用程序列表。',
                'smallType': '应用程序列表',
                'bigType': '设备信息'
            }
        }
    ]);

    hook('android.app.ApplicationPackageManager', [
        {
            'methodName': 'getInstalledPackages',
            'action': action,
            'messages': {
                'detail': '获取已安装应用程序列表。',
                'smallType': '应用程序列表',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getInstalledApplications',
            'action': action,
            'messages': {
                'detail': '获取已安装应用程序列表。',
                'smallType': '应用程序列表',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'queryIntentActivities',
            'action': action,
            'messages': {
                'detail': '查询某个app是否有注册了某个intent（起到了获取其他安装的应用程序信息的作用）。',
                'smallType': '应用程序列表',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('android.app.ActivityManager', [
        {
            'methodName': 'getRunningAppProcesses',
            'action': action,
            'messages': {
                'detail': '获取正在运行的应用程序进程。',
                'smallType': '应用程序列表',
                'bigType': '设备信息'
            }

        },
        {
            'methodName': 'getRunningServiceControlPanel',
            'action': action,
            'messages': {
                'detail': '获取正在运行的服务面板',
                'smallType': '应用程序列表',
                'bigType': '设备信息'
            }
        },
    ]);
    //需排除应用本身
    hookApplicationPackageManagerExceptSelf('getApplicationInfo', action);
    hookApplicationPackageManagerExceptSelf('getPackageInfoAsUser', action);
    hookApplicationPackageManagerExceptSelf('getInstallerPackageName', action);
}

// 获取位置信息
function getGSP() {
    var action = '获取位置信息';

    hook('android.location.LocationManager', [
        {
            'methodName': 'requestLocationUpdates',
            'action': action,
            'messages': {
                'detail': '请求位置更新。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getLastKnownLocation',
            'action': action,
            'messages': {
                'detail': '获取最后一次已知的位置。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getBestProvider',
            'action': action,
            'messages': {
                'detail': '获取最佳位置提供者。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getGnssHardwareModelName',
            'action': action,
            'messages': {
                'detail': '获取GNSS硬件型号名称。',
                'smallType': '设备标识符',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getProvider',
            'action': action,
            'messages': {
                'detail': '从所有可用提供商（WiFi、GPS等）读取位置信息。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'requestSingleUpdate',
            'action': action,
            'messages': {
                'detail': '请求单次位置更新。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getCurrentLocation',
            'action': action,
            'messages': {
                'detail': '获取当前位置。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
    ]);

    hook('android.location.Location', [
        {
            'methodName': 'getAccuracy',
            'action': action,
            'messages': {
                'detail': '获取精度。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getAltitude',
            'action': action,
            'messages': {
                'detail': '获取海拔。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getBearing',
            'action': action,
            'messages': {
                'detail': '获取方位。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getBearingAccuracyDegrees',
            'action': action,
            'messages': {
                'detail': '获取方位精度。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getExtras',
            'action': action,
            'messages': {
                'detail': '获取额外信息。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getLatitude',
            'action': action,
            'messages': {
                'detail': '获取纬度。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getLongitude',
            'action': action,
            'messages': {
                'detail': '获取经度。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getProvider',
            'action': action,
            'messages': {
                'detail': '获取提供者。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
    ]);

    hook('android.location.Geocoder', [
        {
            'methodName': 'getFromLocation',
            'action': action,
            'messages': {
                'detail': '根据给定的经纬度获取地址信息。',
                'smallType': '地理位置',
                'bigType': '位置信息'
            }
        },
        {
            'methodName': 'getFromLocationName',
            'action': action,
            'messages': {
                'detail': '根据地点名称获取相应的地理位置坐标。',
                'smallType': '地理位置',

            }
        },
    ]);

}

// 调用摄像头(hook，防止静默拍照)
function getCamera() {
    var action = '调用摄像头';

    hook('android.hardware.Camera', [
        {
            'methodName': 'open',
            'action': action,
            'messages': {
                'detail': '打开相机。',
                'smallType': '相机',
                'bigType': '媒体信息'
            }
        },
    ]);

    hook('android.hardware.camera2.CameraManager', [
        {
            'methodName': 'openCamera',
            'action': action,
            'messages': {
                'detail': '打开相机。',
                'smallType': '相机',
                'bigType': '媒体信息'
            }
        },
    ]);

    hook('androidx.camera.core.ImageCapture', [
        {
            'methodName': 'takePicture',
            'action': action,
            'messages': {
                'detail': '调用摄像头拍照。',
                'smallType': '相机',
                'bigType': '媒体信息'
            }
        },
    ]);

}

//获取网络信息
function getNetwork() {
    var action = '获取网络信息';

    hook('android.net.wifi.WifiInfo', [
        {
            'methodName': 'getMacAddress',
            'action': action,
            'messages': {
                'detail': '获取MAC地址。',
                'smallType': 'MAC信息',
                'bigType': '设备信息'
            }
        },
    ]);


    hook('java.net.InetAddress', [
        {
            'methodName': 'getHostAddress',
            'action': action,
            'messages': {
                'detail': '获取IP地址。',
                'smallType': 'IP信息',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getAddress',
            'action': action,
            'messages': {
                'detail': '获取IP地址。',
                'smallType': 'IP信息',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('java.net.Inet4Address', [
        {
            'methodName': 'getHostAddress',
            'action': action,
            'messages': {
                'detail': '获取IP地址。',
                'smallType': 'IP信息',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('java.net.Inet6Address', [
        {
            'methodName': 'getHostAddress',
            'action': action,
            'messages': {
                'detail': '获取IP地址。',
                'smallType': 'IP信息',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('java.net.NetworkInterface', [
        {
            'methodName': 'getHardwareAddress',
            'action': action,
            'messages': {
                'detail': '获取MAC地址。',
                'smallType': 'MAC信息',
                'bigType': '设备信息'
            }
        }
    ]);

    hook('java.net.InetSocketAddress', [
        {
            'methodName': 'getHostAddress',
            'action': action,
            'messages': {
                'detail': '获取网络hostaddress信息。',
                'smallType': 'IP信息',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getAddress',
            'action': action,
            'messages': {
                'detail': '获取网络address信息。',
                'smallType': 'IP信息',
                'bigType': '设备信息'
            }
        },
    ]);

    // ip地址
    try {
        var _WifiInfo = Java.use('android.net.wifi.WifiInfo');
        //获取ip
        _WifiInfo.getIpAddress.implementation = function () {
            var temp = this.getIpAddress();
            var _ip = new Array();
            _ip[0] = (temp >>> 24) >>> 0;
            _ip[1] = ((temp << 8) >>> 24) >>> 0;
            _ip[2] = (temp << 16) >>> 24;
            _ip[3] = (temp << 24) >>> 24;
            var _str = String(_ip[3]) + "." + String(_ip[2]) + "." + String(_ip[1]) + "." + String(_ip[0]);
            alertSend(action, {
                'detail': '获取IP地址：' + _str,
                'smallType': 'IP信息',
                'bigType': '设备信息'
            }, '');
            return temp;
        }
    } catch (e) {
        console.log(e)
    }
}

//获取蓝牙设备信息
function getBluetooth() {
    var action = '获取蓝牙设备信息';

    hook('android.bluetooth.BluetoothDevice', [
        {
            'methodName': 'getName',
            'action': action,
            'messages': {
                'detail': '获取蓝牙设备名称。',
                'smallType': '蓝牙信息',
                'bigType': '设备信息'
            }
        },
        {
            'methodName': 'getAddress',
            'action': action,
            'messages': {
                'detail': '获取蓝牙设备mac。',
                'smallType': '蓝牙信息',
                'bigType': '设备信息'
            }
        },
    ]);

    hook('android.bluetooth.BluetoothAdapter', [
        {
            'methodName': 'getName',
            'action': action,
            'messages': {
                'detail': '获取蓝牙设备名称。',
                'smallType': '蓝牙信息',
                'bigType': '设备信息'
            }
        }
    ]);
}

//获取麦克风信息
function getMedia() {
    var action = '获取麦克风'

    hook('android.media.MediaRecorder', [
        {
            'methodName': 'start',
            'action': action,
            'messages': {
                'detail': '获取麦克风。',
                'smallType': '麦克风',
                'bigType': '媒体信息'
            }
        },
        {
            'methodName': 'setAudioSource',
            'action': action,
            'messages': {
                'detail': '捕获音频。',
                'smallType': '麦克风',
                'bigType': '媒体信息'
            }
        }
    ]);
    hook('android.media.AudioRecord', [
        // {
        //     'methodName': 'read',
        //     'action': action,
        //     'messages': {
        //         'detail': '读取音频。',
        //         'smallType': '麦克风',
        //         'bigType': '媒体信息'
        //     }
        // },
        {
            'methodName': 'startRecording',
            'action': action,
            'messages': {
                'detail': '获取麦克风。',
                'smallType': '麦克风',
                'bigType': '媒体信息'
            }
        },
    ]);
}

//获取传感器信息
function getSensor() {
    var action = '获取传感器信息'

    hook('android.hardware.SensorManager', [
        {
            'methodName': 'getSensorList',
            'action': action,
            'messages': {
                'detail': '获取传感器列表。',
                'smallType': '传感器',
                'bigType': '设备信息'
            }
        },
        // {
        //     'methodName': 'getDefaultSensor',
        //     'action': action,
        //     'messages': {
        //         'detail': '获取默认传感器。',
        //         'smallType': '传感器',
        //         'bigType': '设备信息'
        //     }
        // }
    ]);

}

function customHook() {
    var action = '用户自定义hook';

    //自定义hook函数，可自行添加。格式如下：
    // hook('com.zhengjim.myapplication.HookTest', [
    //     {'methodName': 'getPassword', 'action': action, 'messages': '获取zhengjim密码'},
    //     {'methodName': 'getUser', 'action': action, 'messages': '获取zhengjim用户名'},
    // ]);
}

function useModule(moduleList) {
    var _module = {
        'phone': [getPhoneState],
        'system': [getSystemData],
        'app': [getPackageManager],
        'location': [getGSP],
        'network': [getNetwork],
        'camera': [getCamera],
        'bluetooth': [getBluetooth],
        'media': [getMedia],
        'sensor': [getSensor],
        'custom': [customHook]
    };
    var _m = Object.keys(_module);
    var tmp_m = []
    // fixme 无用模块
    if (moduleList['type'] !== 'all') {
        var input_module_data = moduleList['data'].split(',');
        for (i = 0; i < input_module_data.length; i++) {
            if (_m.indexOf(input_module_data[i]) === -1) {
                send({'type': 'noFoundModule', 'data': input_module_data[i]})
            } else {
                tmp_m.push(input_module_data[i])
            }
        }
    }
    switch (moduleList['type']) {
        case 'use':
            _m = tmp_m;
            break;
        case 'nouse':
            for (var i = 0; i < input_module_data.length; i++) {
                for (var j = 0; j < _m.length; j++) {
                    if (_m[j] == input_module_data[i]) {
                        _m.splice(j, 1);
                        j--;
                    }
                }
            }
            break;
    }
    send({'type': 'loadModule', 'data': _m})
    if (_m.length !== 0) {
        for (i = 0; i < _m.length; i++) {
            for (j = 0; j < _module[_m[i]].length; j++) {
                _module[_m[i]][j]();
            }
        }
    }
}

// 脚本入口
function main() {
    try {
        Java.perform(function () {
            console.log('[*] ' + get_format_time() + ' 隐私合规检测敏感接口开始监控...');
            // 向frida发送消息
            send({"type": "isHook"})
            console.log('[*] ' + get_format_time() + ' 检测到安卓版本：' + Java.androidVersion);
            useModule({'type': 'all'})
        });
    } catch (e) {
        console.log(e)
        console.log(e.stacks)
    }
}

// 绕过TracerPid检测 默认关闭，有必要时再自行打开
// setImmediate(ByPassTracerPid);

//在spawn模式下，hook系统API时如javax.crypto.Cipher建议使用setImmediate立即执行，不需要延时
//在spawn模式下，hook应用自己的函数或含壳时，建议使用setTimeout并给出适当的延时(500~5000)

// main();
//setImmediate(main)
// setTimeout(main, 3000);
