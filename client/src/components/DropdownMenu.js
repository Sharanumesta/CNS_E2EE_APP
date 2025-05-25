import React, { useState } from "react";
import { View } from "react-native";
import { Button, Menu } from "react-native-paper";

const DropdownMenu = ({ onSelect, selected, options }) => {
  const [visible, setVisible] = useState(false);

  const openMenu = () => setVisible(true);
  const closeMenu = () => setVisible(false);

  const handleSelect = (option) => {
    onSelect(option);
    closeMenu();
  };

  return (
    <View style={{ zIndex: 9999, alignItems: "center", marginBottom: 20 }}>
      <Menu
        visible={visible}
        onDismiss={closeMenu}
        anchor={<Button mode="outlined" onPress={openMenu}>{selected}</Button>}
      >
        {options.map((opt) => (
          <Menu.Item key={opt.value} title={opt.label} onPress={() => handleSelect(opt.value)} />
        ))}
      </Menu>
    </View>
  );
};

export default DropdownMenu;
