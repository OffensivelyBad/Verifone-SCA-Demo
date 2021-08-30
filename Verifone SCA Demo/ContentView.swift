//
//  ContentView.swift
//  Verifone SCA Demo
//
//  Created by Shawn Roller on 8/29/21.
//

import SwiftUI
import SwiftyRSA

struct ContentView: View {
    var body: some View {
        Text("Hello, world!")
            .padding()
            .onAppear() {
                let b64Keys = generateBase64Keys()
                print(b64Keys.publicKey)
                print(b64Keys.privateKey)
                
                VFDataManager.sharedInstance().calculateMAC()
                
            }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
