import QtQuick 2.15
import QtQuick.Window 2.15

Rectangle {
    id: root
    width: Screen.width
    height: Screen.height
    color: "#050C17" // SDDM ile birebir aynı arka plan rengi

    // --- 1. SİBER IZGARA DOKUSU ---
    Grid {
        anchors.fill: parent
        opacity: 0.15 
        rows: Math.ceil(parent.height / 40)
        columns: Math.ceil(parent.width / 40)
        Repeater {
            model: parent.rows * parent.columns
            Rectangle { width: 1; height: 1; radius: 0.5; color: "#4facfe" }
        }
    }

    // --- 2. YÜZEN SİBER FİGÜRLER ---
    Repeater {
        model: 30 
        Item {
            x: Math.random() * 2500 
            y: Math.random() * 1500
            width: Math.random() * 60 + 20
            height: width
            opacity: Math.random() * 0.15 + 0.05
            
            Rectangle {
                anchors.centerIn: parent
                width: parent.width
                height: index % 3 === 0 ? width : (index % 3 === 1 ? 2 : width)
                radius: index % 3 === 0 ? width / 2 : (index % 3 === 2 ? 4 : 0)
                color: "transparent"
                border.color: index % 2 === 0 ? "#00f2fe" : "#4facfe"
                border.width: 1.5
                RotationAnimation on rotation {
                    loops: Animation.Infinite
                    from: 0; to: index % 2 === 0 ? 360 : -360
                    duration: 20000 + (index * 500)
                }
            }
            NumberAnimation on y {
                loops: Animation.Infinite
                from: y; to: -200
                duration: 30000 + (index * 1000)
            }
        }
    }

    // --- 3. MERKEZE SABİTLENMİŞ YÜKLEME SARMALI ---
    Repeater {
        model: 20 
        Rectangle {
            anchors.centerIn: parent // Fare takibi iptal edildi, merkeze kilitlendi
            width: 40 + index * 50; height: 40 + index * 50
            radius: width / 3; color: "transparent"
            border.color: index % 2 === 0 ? "#00f2fe" : "#4facfe"
            border.width: 1.5 + index * 0.1
            opacity: 0.7 - (index * 0.03)
            
            RotationAnimation on rotation {
                loops: Animation.Infinite; from: 0; to: index % 2 === 0 ? 360 : -360
                duration: 3000 + index * 200
            }
        }
    }

    // --- 4. YÜKLEME METNİ (Nefes Alma Efektli) ---
    Text {
        anchors.centerIn: parent
        text: "Çalışma Alanı Hazırlanıyor..."
        color: "#FFFFFF"
        font.pixelSize: 20
        font.bold: true
        font.family: "Cantarell, sans-serif"
        
        // Yanıp sönme (nefes alma) animasyonu
        SequentialAnimation on opacity {
            loops: Animation.Infinite
            NumberAnimation { from: 0.2; to: 1.0; duration: 1200; easing.type: Easing.InOutSine }
            NumberAnimation { from: 1.0; to: 0.2; duration: 1200; easing.type: Easing.InOutSine }
        }
    }
}
