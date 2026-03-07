import QtQuick 2.15
import QtQuick.Window 2.15
import QtQuick.Controls 2.15

Rectangle {
    id: root
    width: Screen.width
    height: Screen.height
    color: "#050C17"

    property bool onayBekleniyor: false
    property string secilenIslem: ""

    // --- YENİ: YÜZEN SİBER FİGÜRLER (GEOMETRİK DESENLER) ---
    // Arka planda yavaşça yukarı doğru süzülen şekiller
    Repeater {
        model: 40 
        Item {
            x: Math.random() * 2500 
            y: Math.random() * 1500
            width: Math.random() * 60 + 20
            height: width
            opacity: Math.random() * 0.15 + 0.05 // Göz yormaması için hafif saydam
            z: 0

            Rectangle {
                anchors.centerIn: parent
                width: parent.width
                // index değerine göre daire, siber çizgi veya kare oluşturur
                height: index % 3 === 0 ? width : (index % 3 === 1 ? 2 : width)
                radius: index % 3 === 0 ? width / 2 : (index % 3 === 2 ? 4 : 0)
                color: "transparent"
                border.color: index % 2 === 0 ? "#00f2fe" : "#4facfe"
                border.width: 1.5

                // Kendi etrafında ağır ağır dönüş
                RotationAnimation on rotation {
                    loops: Animation.Infinite
                    from: 0; to: index % 2 === 0 ? 360 : -360
                    duration: 20000 + (index * 500)
                }
            }

            // Yukarı doğru süzülme animasyonu
            NumberAnimation on y {
                loops: Animation.Infinite
                from: y
                to: -200
                duration: 30000 + (index * 1000)
            }
        }
    }

    // --- SİBER IZGARA DOKUSU ---
    Grid {
        id: backgroundPattern
        anchors.fill: parent
        opacity: 0.15 
        z: 0
        rows: Math.ceil(parent.height / 40)
        columns: Math.ceil(parent.width / 40)
        
        Repeater {
            model: parent.rows * parent.columns
            Rectangle { width: 1; height: 1; radius: 0.5; color: "#4facfe" }
        }
    }

    // --- ARKA PLAN VE SARMAL ---
    MouseArea {
        id: touchArea
        anchors.fill: parent; hoverEnabled: true
        property real mX: parent.width / 2; property real mY: parent.height / 2
        onPositionChanged: { mX = mouse.x; mY = mouse.y }
    }

    Repeater {
        model: 20 
        Rectangle {
            width: 40 + index * 50; height: 40 + index * 50
            radius: width / 3; color: "transparent"
            border.color: index % 2 === 0 ? "#00f2fe" : "#4facfe"
            border.width: 1.5 + index * 0.1
            opacity: 0.7 - (index * 0.03)
            z: 1 
            x: touchArea.mX - width / 2; y: touchArea.mY - height / 2
            Behavior on x { SpringAnimation { spring: 2.0; damping: 0.2; mass: 1.0 + index * 0.15 } }
            Behavior on y { SpringAnimation { spring: 2.0; damping: 0.2; mass: 1.0 + index * 0.15 } }
            RotationAnimation on rotation {
                loops: Animation.Infinite; from: 0; to: index % 2 === 0 ? 360 : -360
                duration: 3000 + index * 200
            }
        }
    }

    // --- BUĞLANMA / ODAKLANMA EFEKTİ ---
    Rectangle {
        id: odakKarartici
        anchors.fill: parent
        color: "#E60A192F"
        z: 8 
        opacity: (sifreGirisi.activeFocus || root.onayBekleniyor) ? 1.0 : 0.0
        Behavior on opacity { NumberAnimation { duration: 500; easing.type: Easing.InOutQuad } }
    }

    // --- MERKEZ CAM KUTU (PROFİL VE ŞİFRE) ---
    Rectangle {
        id: loginPaneli
        width: 380; height: 500 
        anchors.centerIn: parent
        color: "#B30A192F"; radius: 24; border.color: "#40FFFFFF"; border.width: 1.5
        z: 10
        
        opacity: root.onayBekleniyor ? 0.2 : 1.0
        Behavior on opacity { NumberAnimation { duration: 300 } }

        MouseArea { 
            anchors.fill: parent
            onClicked: sifreGirisi.forceActiveFocus()
        } 

        Rectangle {
            id: avatarCircle
            width: 80; height: 80; radius: 40
            anchors.top: parent.top; anchors.topMargin: 35; anchors.horizontalCenter: parent.horizontalCenter
            color: "#1AFFFFFF"; border.color: "#00f2fe"; border.width: 2
            Text {
                anchors.centerIn: parent
                text: userModel.lastUser ? userModel.lastUser.charAt(0).toUpperCase() : "👤"
                color: "#00f2fe"; font.pixelSize: 36; font.bold: true
            }
        }

        Text {
            id: userNameText
            anchors.top: avatarCircle.bottom; anchors.topMargin: 15; anchors.horizontalCenter: parent.horizontalCenter
            text: userModel.lastUser ? userModel.lastUser : "Kullanıcı"
            color: "#FFFFFF"; font.pixelSize: 22; font.bold: true; font.family: "Cantarell, sans-serif"
        }

        Rectangle {
            id: sifreKutusuArkaplan
            width: 280; height: 50
            anchors.top: userNameText.bottom; anchors.topMargin: 30; anchors.horizontalCenter: parent.horizontalCenter
            color: "#33FFFFFF"; radius: 12; border.color: "#80FFFFFF"; border.width: 1

            TextInput {
                id: sifreGirisi
                anchors.fill: parent; anchors.leftMargin: 15; anchors.rightMargin: 15
                verticalAlignment: TextInput.AlignVCenter; color: "#FFFFFF"; font.pixelSize: 16
                echoMode: TextInput.Password; passwordCharacter: "•"
                focus: false 
                
                Text {
                    id: placeholder
                    text: "Şifrenizi girmek için tıklayın..."; color: "#A0FFFFFF"; font.pixelSize: 14
                    anchors.verticalCenter: parent.verticalCenter
                    visible: !sifreGirisi.text && !sifreGirisi.activeFocus 
                }
                
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.IBeamCursor
                    onClicked: sifreGirisi.forceActiveFocus()
                }

                onAccepted: sddm.login(userModel.lastUser, sifreGirisi.text, 0)
            }
        }

        Rectangle {
            id: girisButonu
            width: 280; height: 50
            anchors.top: sifreKutusuArkaplan.bottom; anchors.topMargin: 20; anchors.horizontalCenter: parent.horizontalCenter
            color: "#00f2fe"; radius: 12
            Text { anchors.centerIn: parent; text: "Giriş Yap"; color: "#0A192F"; font.pixelSize: 18; font.bold: true }
            MouseArea {
                anchors.fill: parent; cursorShape: Qt.PointingHandCursor 
                onEntered: girisButonu.color = "#4facfe"; onExited: girisButonu.color = "#00f2fe"
                onClicked: sddm.login(userModel.lastUser, sifreGirisi.text, 0)
            }
        }
    }

    // --- GÜÇ KONTROLLERİ ---
    Row {
        anchors.bottom: parent.bottom; anchors.bottomMargin: 40; anchors.right: parent.right; anchors.rightMargin: 50
        spacing: 15; z: 10
        opacity: root.onayBekleniyor ? 0.0 : 1.0
        Behavior on opacity { NumberAnimation { duration: 300 } }

        Rectangle {
            width: 110; height: 40; color: "#1AFFFFFF"; radius: 8; border.color: "#40FFFFFF"; border.width: 1
            Text { anchors.centerIn: parent; text: "Derin Uyku"; color: "white"; font.pixelSize: 13 }
            MouseArea {
                anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onEntered: parent.color = "#4facfe"; onExited: parent.color = "#1AFFFFFF"
                onClicked: { root.secilenIslem = "Derin Uyku"; root.onayBekleniyor = true; }
            }
        }

        Rectangle {
            width: 80; height: 40; color: "#1AFFFFFF"; radius: 8; border.color: "#40FFFFFF"; border.width: 1
            Text { anchors.centerIn: parent; text: "Uyut"; color: "white"; font.pixelSize: 13 }
            MouseArea {
                anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onEntered: parent.color = "#4facfe"; onExited: parent.color = "#1AFFFFFF"
                onClicked: { root.secilenIslem = "Uyut"; root.onayBekleniyor = true; }
            }
        }

        Rectangle {
            width: 130; height: 40; color: "#1AFFFFFF"; radius: 8; border.color: "#40FFFFFF"; border.width: 1
            Text { anchors.centerIn: parent; text: "Yeniden Başlat"; color: "white"; font.pixelSize: 13 }
            MouseArea {
                anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onEntered: parent.color = "#4facfe"; onExited: parent.color = "#1AFFFFFF"
                onClicked: { root.secilenIslem = "Yeniden Başlat"; root.onayBekleniyor = true; }
            }
        }

        Rectangle {
            width: 90; height: 40; color: "#D90A192F"; radius: 8; border.color: "#00f2fe"; border.width: 1 
            Text { anchors.centerIn: parent; text: "Kapat"; color: "#00f2fe"; font.pixelSize: 13; font.bold: true }
            MouseArea {
                anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onEntered: { parent.color = "#00f2fe"; parent.children[0].color = "#0A192F" }
                onExited: { parent.color = "#D90A192F"; parent.children[0].color = "#00f2fe" }
                onClicked: { root.secilenIslem = "Kapat"; root.onayBekleniyor = true; }
            }
        }
    }

    // --- ONAY KUTUSU ---
    Rectangle {
        id: onayKutusu
        width: 320; height: 180
        anchors.centerIn: parent
        z: 20; color: "#0A192F"; radius: 16; border.color: "#00f2fe"; border.width: 1.5
        opacity: root.onayBekleniyor ? 1.0 : 0.0
        visible: opacity > 0
        Behavior on opacity { NumberAnimation { duration: 400; easing.type: Easing.OutBack } }

        Text {
            anchors.top: parent.top; anchors.topMargin: 35; anchors.horizontalCenter: parent.horizontalCenter
            text: root.secilenIslem + " işlemi başlatılacak.\nEmin misiniz?"
            color: "white"; font.pixelSize: 16; horizontalAlignment: Text.AlignHCenter
        }

        Row {
            anchors.bottom: parent.bottom; anchors.bottomMargin: 25; anchors.horizontalCenter: parent.horizontalCenter
            spacing: 20
            Rectangle {
                width: 100; height: 40; radius: 8; color: "#1AFFFFFF"; border.color: "#80FFFFFF"; border.width: 1
                Text { anchors.centerIn: parent; text: "İptal"; color: "white" }
                MouseArea {
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onEntered: parent.color = "#33FFFFFF"; onExited: parent.color = "#1AFFFFFF"
                    onClicked: { root.onayBekleniyor = false; }
                }
            }
            Rectangle {
                width: 100; height: 40; radius: 8; color: "#00f2fe"
                Text { anchors.centerIn: parent; text: "Evet"; color: "#0A192F"; font.bold: true }
                MouseArea {
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onEntered: parent.color = "#4facfe"; onExited: parent.color = "#00f2fe"
                    onClicked: {
                        if(root.secilenIslem === "Kapat") sddm.powerOff();
                        else if(root.secilenIslem === "Yeniden Başlat") sddm.reboot();
                        else if(root.secilenIslem === "Uyut") sddm.suspend();
                        else if(root.secilenIslem === "Derin Uyku") sddm.hibernate();
                    }
                }
            }
        }
    }
}
