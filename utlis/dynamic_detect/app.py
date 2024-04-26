# 获取app列表
import frida
import base64

def getAppList():
    app_list = []
    packages = {}
    try:
        try:
            device = frida.get_usb_device(timeout=5)
        except:
            device = frida.get_remote_device()
        apps = device.enumerate_applications(scope="full")
    except Exception as e:
        print("未找到设备: " + str(e))
        return []
    for i in apps:
        if i.identifier in packages:
            continue
        packages[i.identifier] = 2
        if len(i.parameters["icons"]) != 0:
            i.parameters["icons"][0]["image"] = (
                    "data:image/"
                    + i.parameters["icons"][0]["format"]
                    + ";base64,"
                    + base64.b64encode(i.parameters["icons"][0]["image"]).decode("utf-8")
            )
            app_list.append(
                {
                    "name": i.name,
                    "package": i.identifier,
                    "version": i.parameters.get("version", "-"),
                    "icon": i.parameters["icons"][0]["image"],
                }
            )
        else:
            app_list.append(
                {
                    "name": i.name,
                    "package": i.identifier,
                    "version": i.parameters.get("version", "-"),
                    "icon": "",
                }
            )
    return app_list